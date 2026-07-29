package app

import (
	"context"
	"errors"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type HostKeyProbe interface {
	Probe(context.Context, string, uint16) (string, error)
}

type SSHHostKeyProbe struct{}

var errHostKeyCaptured = errors.New("host key captured")

func (SSHHostKeyProbe) Probe(ctx context.Context, host string, port uint16) (string, error) {
	if ctx == nil || host == "" || port == 0 {
		return "", ErrInvalidServer
	}
	address := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return "", ErrHostKeyProbe
	}
	defer connection.Close()
	stopContextWatch := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopContextWatch()

	var fingerprint string
	config := &ssh.ClientConfig{
		User: "aegis-host-key-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			return errHostKeyCaptured
		},
	}
	_, _, _, _ = ssh.NewClientConn(connection, address, config)
	if fingerprint == "" {
		if ctx.Err() != nil {
			return "", ErrHostKeyProbe
		}
		return "", ErrHostKeyProbe
	}
	return fingerprint, nil
}
