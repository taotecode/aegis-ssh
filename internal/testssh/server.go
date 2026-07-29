package testssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/taotecode/aegis-ssh/internal/vault"
	"golang.org/x/crypto/ssh"
)

type Output struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Handler must return after its context is canceled.
type Handler func(context.Context) Output

type Server struct {
	Host        string
	Port        uint16
	Fingerprint string

	listener net.Listener
	config   *ssh.ServerConfig

	mu       sync.RWMutex
	handlers map[string]Handler
	conns    map[net.Conn]struct{}
	closed   chan struct{}
	close    sync.Once
	wg       sync.WaitGroup
}

func Start(t testing.TB, username, password string) *Server {
	t.Helper()
	config := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, candidate []byte) (*ssh.Permissions, error) {
			userOK := subtle.ConstantTimeCompare([]byte(metadata.User()), []byte(username)) == 1
			passwordOK := subtle.ConstantTimeCompare(candidate, []byte(password)) == 1
			if userOK && passwordOK {
				return nil, nil
			}
			return nil, errors.New("authentication rejected")
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("public key authentication rejected")
		},
	}
	return start(t, config)
}

func StartWithPublicKey(t testing.TB, username string, authorizedKey ssh.PublicKey) *Server {
	t.Helper()
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, errors.New("password authentication rejected")
		},
		PublicKeyCallback: func(metadata ssh.ConnMetadata, candidate ssh.PublicKey) (*ssh.Permissions, error) {
			userOK := subtle.ConstantTimeCompare([]byte(metadata.User()), []byte(username)) == 1
			keyOK := authorizedKey != nil && subtle.ConstantTimeCompare(candidate.Marshal(), authorizedKey.Marshal()) == 1
			if userOK && keyOK {
				return nil, nil
			}
			return nil, errors.New("public key authentication rejected")
		},
	}
	return start(t, config)
}

func start(t testing.TB, config *ssh.ServerConfig) *Server {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create SSH host signer: %v", err)
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH test server: %v", err)
	}
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("parse SSH test server address: %v", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		listener.Close()
		t.Fatalf("parse SSH test server port: %v", err)
	}

	server := &Server{
		Host:        host,
		Port:        uint16(port),
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		listener:    listener,
		config:      config,
		handlers:    make(map[string]Handler),
		conns:       make(map[net.Conn]struct{}),
		closed:      make(chan struct{}),
	}
	server.Handle("printf ok", func(context.Context) Output { return Output{Stdout: "ok"} })
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(server.Close)
	return server
}

func (s *Server) Secret(username, password string) vault.ServerSecret {
	return vault.ServerSecret{
		Host:            s.Host,
		Port:            s.Port,
		User:            username,
		Password:        []byte(password),
		HostFingerprint: s.Fingerprint,
	}
}

func (s *Server) Handle(command string, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = handler
}

func (s *Server) Close() {
	s.close.Do(func() {
		close(s.closed)
		_ = s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}
		s.mu.Lock()
		select {
		case <-s.closed:
			s.mu.Unlock()
			_ = conn.Close()
			return
		default:
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()

	serverConn, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = serverConn.Wait()
		cancel()
	}()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		ch, reqs, err := channel.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go s.serveSession(ctx, ch, reqs)
	}
}

func (s *Server) serveSession(connCtx context.Context, ch ssh.Channel, requests <-chan *ssh.Request) {
	defer s.wg.Done()
	defer ch.Close()

	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		command, ok := parseExecCommand(request.Payload)
		if !ok {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		s.runHandler(connCtx, ch, requests, command)
		return
	}
}

func (s *Server) runHandler(connCtx context.Context, ch ssh.Channel, requests <-chan *ssh.Request, command string) {
	ctx, cancel := context.WithCancel(connCtx)
	defer cancel()

	s.mu.RLock()
	handler := s.handlers[command]
	s.mu.RUnlock()
	if handler == nil {
		handler = func(context.Context) Output {
			return Output{Stderr: "command not registered", ExitCode: 127}
		}
	}

	result := make(chan Output, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		result <- handler(ctx)
	}()
	for {
		select {
		case output := <-result:
			var writes sync.WaitGroup
			writes.Add(2)
			go func() {
				defer writes.Done()
				_, _ = ch.Write([]byte(output.Stdout))
			}()
			go func() {
				defer writes.Done()
				_, _ = ch.Stderr().Write([]byte(output.Stderr))
			}()
			writes.Wait()
			status := struct{ Status uint32 }{Status: uint32(output.ExitCode)}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
			return
		case request, ok := <-requests:
			if !ok {
				cancel()
				return
			}
			_ = request.Reply(false, nil)
		case <-connCtx.Done():
			cancel()
			return
		case <-s.closed:
			cancel()
			return
		}
	}
}

func parseExecCommand(payload []byte) (string, bool) {
	if len(payload) < 4 {
		return "", false
	}
	length := int(binary.BigEndian.Uint32(payload[:4]))
	if length != len(payload)-4 {
		return "", false
	}
	return string(payload[4:]), true
}
