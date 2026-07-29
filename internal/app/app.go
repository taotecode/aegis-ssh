package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chenjw/aegis-ssh/internal/approval"
	"github.com/chenjw/aegis-ssh/internal/audit"
	"github.com/chenjw/aegis-ssh/internal/broker"
	"github.com/chenjw/aegis-ssh/internal/config"
	"github.com/chenjw/aegis-ssh/internal/mcpserver"
	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/chenjw/aegis-ssh/internal/paths"
	"github.com/chenjw/aegis-ssh/internal/policy"
	"github.com/chenjw/aegis-ssh/internal/sshclient"
	"github.com/chenjw/aegis-ssh/internal/vault"
)

const (
	Version       = "0.1.0"
	PolicyVersion = "1"

	defaultConnectTimeout = 10 * time.Second
	defaultCommandTimeout = 30 * time.Second
	defaultMaxOutput      = int64(1 << 20)
)

var (
	ErrUsage              = errors.New("invalid command usage")
	ErrSecretArgument     = errors.New("connection secrets must not be supplied in command arguments")
	ErrSecretEnvironment  = errors.New("connection secrets must not be supplied through environment variables")
	ErrAlreadyInitialized = errors.New("aegis-ssh is already initialized")
	ErrNotInitialized     = errors.New("aegis-ssh is not initialized")
	ErrDaemonRunning      = errors.New("stop the daemon before changing servers")
	ErrDaemonUnavailable  = errors.New("broker daemon unavailable")
	ErrInvalidAlias       = errors.New("invalid server alias")
	ErrInvalidServer      = errors.New("invalid server details")
	ErrServerExists       = errors.New("server alias already exists")
	ErrServerNotFound     = errors.New("server alias not found")
	ErrHostKeyProbe       = errors.New("unable to probe SSH host key")
	ErrHostKeyUnconfirmed = errors.New("SSH host key was not confirmed")
	ErrPasswordMismatch   = errors.New("master passwords do not match")
	ErrStorage            = errors.New("secure local storage operation failed")
)

type BrokerClient interface {
	Status(context.Context) (model.BrokerStatus, error)
	ListServers(context.Context) ([]model.ServerSummary, error)
	Execute(context.Context, model.ExecuteRequest) (model.ExecuteResult, error)
	ExecuteApproved(context.Context, model.ApprovedRequest) (model.ExecuteResult, error)
	Lock(context.Context) error
}

type Dependencies struct {
	Root         string
	Stdout       io.Writer
	Stderr       io.Writer
	OpenTerminal func() (Terminal, error)
	HostKeyProbe HostKeyProbe
	BrokerClient func(string) BrokerClient
}

type App struct {
	deps Dependencies
}

func New(deps Dependencies) *App {
	if deps.Stdout == nil {
		deps.Stdout = os.Stdout
	}
	if deps.Stderr == nil {
		deps.Stderr = os.Stderr
	}
	if deps.OpenTerminal == nil {
		deps.OpenTerminal = OpenTerminal
	}
	if deps.HostKeyProbe == nil {
		deps.HostKeyProbe = SSHHostKeyProbe{}
	}
	if deps.BrokerClient == nil {
		deps.BrokerClient = func(path string) BrokerClient { return broker.NewClient(path) }
	}
	return &App{deps: deps}
}

func (application *App) Run(ctx context.Context, args []string) error {
	if application == nil || ctx == nil {
		return ErrUsage
	}
	if hasSecretArgument(args) {
		return ErrSecretArgument
	}
	if hasSecretEnvironment() {
		return ErrSecretEnvironment
	}
	if len(args) == 0 {
		application.printHelp()
		return ErrUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		if len(args) != 1 {
			return ErrUsage
		}
		application.printHelp()
		return nil
	case "init":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.initialize()
	case "daemon":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.daemon(ctx)
	case "lock":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.lock(ctx)
	case "status":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.status(ctx)
	case "server":
		return application.server(ctx, args[1:])
	case "exec":
		return application.execute(ctx, args[1:])
	case "mcp":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.runMCP(ctx)
	default:
		return ErrUsage
	}
}

func (application *App) initialize() error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	if exists(layout.ConfigFile) || exists(layout.VaultFile) {
		return ErrAlreadyInitialized
	}
	lifecycle, err := acquireLifecycleLock(layout.Root)
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if exists(layout.ConfigFile) || exists(layout.VaultFile) {
		return ErrAlreadyInitialized
	}
	terminal, err := application.deps.OpenTerminal()
	if err != nil {
		return err
	}
	defer terminal.Close()
	master, err := ReadSecret(terminal, "Master password: ")
	if err != nil {
		return err
	}
	defer Zero(master)
	confirmation, err := ReadSecret(terminal, "Confirm master password: ")
	if err != nil {
		return err
	}
	defer Zero(confirmation)
	if len(master) != len(confirmation) || subtle.ConstantTimeCompare(master, confirmation) != 1 {
		return ErrPasswordMismatch
	}
	store := vault.Store{Path: layout.VaultFile}
	if err := store.Initialize(master); err != nil {
		return ErrStorage
	}
	cfg := defaultConfig()
	if err := saveConfigVerified(layout.ConfigFile, cfg); err != nil {
		_ = os.Remove(layout.VaultFile)
		_ = os.Remove(layout.ConfigFile)
		return ErrStorage
	}
	_, _ = fmt.Fprintln(application.deps.Stdout, "aegis-ssh initialized")
	return nil
}

func (application *App) server(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return ErrUsage
	}
	switch args[0] {
	case "add":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.addServer(ctx)
	case "edit":
		if len(args) != 2 {
			return ErrUsage
		}
		return application.editServer(ctx, args[1])
	case "remove":
		if len(args) != 2 {
			return ErrUsage
		}
		return application.removeServer(ctx, args[1])
	case "list":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.listServers()
	default:
		return ErrUsage
	}
}

func (application *App) addServer(ctx context.Context) error {
	var addedAlias string
	err := application.withUnlockedVault(ctx, func(terminal Terminal, cfg *config.Config, data *vault.Data) error {
		alias, err := ReadText(terminal, "Alias: ")
		if err != nil || !validAlias(alias) {
			return ErrInvalidAlias
		}
		if _, ok := cfg.Servers[alias]; ok {
			return ErrServerExists
		}
		description, secret, err := application.readServer(ctx, terminal)
		if err != nil {
			return err
		}
		cfg.Servers[alias] = config.ServerPublic{Description: description}
		data.Servers[alias] = secret
		addedAlias = alias
		return nil
	})
	if err == nil {
		_, _ = fmt.Fprintf(application.deps.Stdout, "server %s added\n", addedAlias)
	}
	return err
}

func (application *App) editServer(ctx context.Context, alias string) error {
	if !validAlias(alias) {
		return ErrInvalidAlias
	}
	err := application.withUnlockedVault(ctx, func(terminal Terminal, cfg *config.Config, data *vault.Data) error {
		if _, ok := cfg.Servers[alias]; !ok {
			return ErrServerNotFound
		}
		description, secret, err := application.readServer(ctx, terminal)
		if err != nil {
			return err
		}
		old := data.Servers[alias]
		vault.Zero(old.Password)
		cfg.Servers[alias] = config.ServerPublic{Description: description}
		data.Servers[alias] = secret
		return nil
	})
	if err == nil {
		_, _ = fmt.Fprintf(application.deps.Stdout, "server %s updated\n", alias)
	}
	return err
}

func (application *App) removeServer(ctx context.Context, alias string) error {
	if !validAlias(alias) {
		return ErrInvalidAlias
	}
	err := application.withUnlockedVault(ctx, func(terminal Terminal, cfg *config.Config, data *vault.Data) error {
		if _, ok := cfg.Servers[alias]; !ok {
			return ErrServerNotFound
		}
		confirmed, err := ConfirmExact(terminal, "Type the alias to remove: ", alias)
		if err != nil {
			return err
		}
		if !confirmed {
			return ErrUsage
		}
		secret := data.Servers[alias]
		vault.Zero(secret.Password)
		delete(cfg.Servers, alias)
		delete(data.Servers, alias)
		return nil
	})
	if err == nil {
		_, _ = fmt.Fprintf(application.deps.Stdout, "server %s removed\n", alias)
	}
	return err
}

func (application *App) readServer(ctx context.Context, terminal Terminal) (string, vault.ServerSecret, error) {
	description, err := ReadText(terminal, "Description: ")
	if err != nil {
		return "", vault.ServerSecret{}, err
	}
	host, err := ReadText(terminal, "Host: ")
	if err != nil || host == "" {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	portText, err := ReadText(terminal, "Port: ")
	if err != nil {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portValue == 0 {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	user, err := ReadText(terminal, "User: ")
	if err != nil || user == "" {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	probeCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	fingerprint, err := application.deps.HostKeyProbe.Probe(probeCtx, host, uint16(portValue))
	cancel()
	if err != nil || fingerprint == "" {
		return "", vault.ServerSecret{}, ErrHostKeyProbe
	}
	_, _ = fmt.Fprintf(terminal, "Host key fingerprint: %s\n", fingerprint)
	confirmed, err := ConfirmExact(terminal, "Type TRUST to pin this host key: ", "TRUST")
	if err != nil {
		return "", vault.ServerSecret{}, err
	}
	if !confirmed {
		return "", vault.ServerSecret{}, ErrHostKeyUnconfirmed
	}
	password, err := ReadSecret(terminal, "SSH password: ")
	if err != nil {
		return "", vault.ServerSecret{}, err
	}
	return description, vault.ServerSecret{
		Host: host, Port: uint16(portValue), User: user,
		Password: password, HostFingerprint: fingerprint,
	}, nil
}

func (application *App) withUnlockedVault(ctx context.Context, mutate func(Terminal, *config.Config, *vault.Data) error) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	lifecycle, err := acquireLifecycleLock(layout.Root)
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if err := application.requireDaemonStopped(ctx, layout.SocketFile); err != nil {
		return err
	}
	cfg, err := config.Load(layout.ConfigFile)
	if err != nil {
		return ErrNotInitialized
	}
	if cfg.Servers == nil {
		cfg.Servers = make(map[string]config.ServerPublic)
	}
	terminal, err := application.deps.OpenTerminal()
	if err != nil {
		return err
	}
	defer terminal.Close()
	master, err := ReadSecret(terminal, "Master password: ")
	if err != nil {
		return err
	}
	defer Zero(master)
	store := vault.Store{Path: layout.VaultFile}
	data, err := store.Load(master)
	if err != nil {
		return ErrStorage
	}
	defer zeroVaultData(&data)
	if data.Servers == nil {
		data.Servers = make(map[string]vault.ServerSecret)
	}
	original := cloneVaultData(data)
	defer zeroVaultData(&original)
	originalConfig := cloneConfig(cfg)
	if err := mutate(terminal, &cfg, &data); err != nil {
		return err
	}
	if err := saveConfigVerified(layout.ConfigFile, cfg); err != nil {
		return ErrStorage
	}
	if err := saveVaultVerified(store, master, data); err != nil {
		_ = saveConfigVerified(layout.ConfigFile, originalConfig)
		return ErrStorage
	}
	return nil
}

func (application *App) listServers() error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	cfg, err := config.Load(layout.ConfigFile)
	if err != nil {
		return ErrNotInitialized
	}
	aliases := make([]string, 0, len(cfg.Servers))
	for alias := range cfg.Servers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		description := cfg.Servers[alias].Description
		if description == "" {
			_, _ = fmt.Fprintln(application.deps.Stdout, alias)
		} else {
			_, _ = fmt.Fprintf(application.deps.Stdout, "%s\t%s\n", alias, description)
		}
	}
	return nil
}

func (application *App) daemon(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	lifecycle, err := acquireLifecycleLock(layout.Root)
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if running, checkErr := application.daemonReachable(ctx, layout.SocketFile); checkErr == nil && running {
		return ErrDaemonRunning
	}
	cfg, err := config.Load(layout.ConfigFile)
	if err != nil {
		return ErrNotInitialized
	}
	terminal, err := application.deps.OpenTerminal()
	if err != nil {
		return err
	}
	master, err := ReadSecret(terminal, "Master password: ")
	_ = terminal.Close()
	if err != nil {
		return err
	}
	defer Zero(master)
	data, err := (vault.Store{Path: layout.VaultFile}).Load(master)
	if err != nil {
		return ErrStorage
	}
	if !consistentAliases(cfg, data) {
		zeroVaultData(&data)
		return ErrStorage
	}
	secrets := newMemorySecrets(data)
	zeroVaultData(&data)
	defer secrets.Lock()

	connectTimeout, commandTimeout, maxOutput, err := validateDefaults(cfg.Defaults)
	if err != nil {
		return ErrStorage
	}
	logger, err := audit.New(layout.AuditDir, audit.Options{Backups: 3})
	if err != nil {
		return ErrStorage
	}
	redactor := outputRedactor{}
	service, err := broker.NewService(broker.ServiceOptions{
		Secrets: secrets, Analyzer: policy.NewAnalyzer(),
		Approvals: approval.NewStore(time.Now, rand.Reader), Executor: sshclient.NewWithConnectTimeout(connectTimeout),
		Redactor: redactor, Auditor: logger, Now: time.Now,
		AllowAuditFailOpen: !cfg.Defaults.AuditFailClosed,
		DefaultTimeout:     commandTimeout, DefaultMaxOutput: maxOutput,
		Servers: publicServers(cfg, secrets), Version: Version, PolicyVersion: PolicyVersion,
	})
	if err != nil {
		return ErrStorage
	}
	daemonCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	wrapped := &daemonService{Service: service, secrets: secrets, cancel: cancel}
	if err := broker.NewServer(layout.SocketFile, wrapped).Serve(daemonCtx); err != nil {
		return err
	}
	return nil
}

func (application *App) lock(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	if err := application.deps.BrokerClient(layout.SocketFile).Lock(ctx); err != nil {
		return ErrDaemonUnavailable
	}
	_, _ = fmt.Fprintln(application.deps.Stdout, "aegis-ssh daemon locked")
	return nil
}

func (application *App) status(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	status, err := application.deps.BrokerClient(layout.SocketFile).Status(ctx)
	if err != nil {
		_, _ = fmt.Fprintln(application.deps.Stdout, "daemon: unavailable")
		return nil
	}
	state := "ready"
	if status.VaultLocked {
		state = "locked"
	}
	_, _ = fmt.Fprintf(application.deps.Stdout, "daemon: %s\nversion: %s\npolicy: %s\n", state, status.Version, status.PolicyVersion)
	return nil
}

func (application *App) execute(ctx context.Context, args []string) error {
	if len(args) != 3 || !validAlias(args[0]) || args[1] != "--" {
		return ErrUsage
	}
	command := args[2]
	if strings.TrimSpace(command) == "" {
		return ErrUsage
	}
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	client := application.deps.BrokerClient(layout.SocketFile)
	result, err := client.Execute(ctx, model.ExecuteRequest{ServerAlias: args[0], Command: command})
	if err != nil {
		return ErrDaemonUnavailable
	}
	if result.Status == model.StatusRequiresApproval {
		if result.Approval == nil {
			return model.ErrApproval
		}
		_, _ = fmt.Fprintln(application.deps.Stderr, result.Approval.Message)
		terminal, openErr := application.deps.OpenTerminal()
		if openErr != nil {
			return openErr
		}
		confirmed, confirmErr := ConfirmExact(terminal, "Type the approval code to continue: ", result.Approval.Code)
		_ = terminal.Close()
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			return model.ErrApproval
		}
		result, err = client.ExecuteApproved(ctx, model.ApprovedRequest{ApprovalID: result.Approval.ID, ApprovalCode: result.Approval.Code})
		if err != nil {
			return ErrDaemonUnavailable
		}
	}
	return application.printExecuteResult(result)
}

func (application *App) printExecuteResult(result model.ExecuteResult) error {
	if result.Stdout != "" {
		_, _ = io.WriteString(application.deps.Stdout, result.Stdout)
	}
	if result.Stderr != "" {
		_, _ = io.WriteString(application.deps.Stderr, result.Stderr)
	}
	if result.Status != model.StatusCompleted {
		if result.Error != nil {
			return result.Error
		}
		return model.ErrConnection
	}
	if result.ExitCode != 0 {
		return &ExitCodeError{Code: result.ExitCode}
	}
	return nil
}

func (application *App) runMCP(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	return mcpserver.New(application.deps.BrokerClient(layout.SocketFile)).RunStdio(ctx)
}

func (application *App) requireDaemonStopped(ctx context.Context, socket string) error {
	running, err := application.daemonReachable(ctx, socket)
	if err == nil && running {
		return ErrDaemonRunning
	}
	if err != nil && !errors.Is(err, broker.ErrUnavailable) {
		return ErrDaemonRunning
	}
	return nil
}

func (application *App) daemonReachable(ctx context.Context, socket string) (bool, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	status, err := application.deps.BrokerClient(socket).Status(checkCtx)
	return err == nil && status.DaemonReachable, err
}

func (application *App) layout() (paths.Paths, error) {
	root := application.deps.Root
	if root == "" {
		var err error
		root, err = paths.DefaultRoot()
		if err != nil {
			return paths.Paths{}, err
		}
	}
	return paths.EnsureLayout(root)
}

func (application *App) printHelp() {
	_, _ = io.WriteString(application.deps.Stdout, `Usage: aegis-ssh <command>

Commands:
  init                         Initialize encrypted local storage
  daemon                       Unlock and run the SSH broker
  lock                         Clear daemon credentials and stop it
  status                       Show broker availability
  server add                   Add a server interactively
  server edit <alias>          Replace a server interactively
  server remove <alias>        Remove a server
  server list                  List public aliases and descriptions
  exec <alias> -- '<command>'  Execute an exact remote shell string
  mcp                          Run the standard stdio MCP server
`)
}

type ExitCodeError struct {
	Code int
}

func (err *ExitCodeError) Error() string {
	return fmt.Sprintf("remote command exited with status %d", err.Code)
}

type memorySecrets struct {
	mu      sync.RWMutex
	servers map[string]vault.ServerSecret
}

func newMemorySecrets(data vault.Data) *memorySecrets {
	return &memorySecrets{servers: cloneVaultData(data).Servers}
}

func (secrets *memorySecrets) Lookup(alias string) (vault.ServerSecret, bool) {
	secrets.mu.RLock()
	defer secrets.mu.RUnlock()
	secret, ok := secrets.servers[alias]
	secret.Password = append([]byte(nil), secret.Password...)
	return secret, ok
}

func (secrets *memorySecrets) Available(alias string) bool {
	secrets.mu.RLock()
	defer secrets.mu.RUnlock()
	_, ok := secrets.servers[alias]
	return ok
}

func (secrets *memorySecrets) Lock() {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	for alias, secret := range secrets.servers {
		vault.Zero(secret.Password)
		delete(secrets.servers, alias)
	}
}

type daemonService struct {
	*broker.Service
	secrets *memorySecrets
	cancel  context.CancelFunc
	once    sync.Once
}

func (service *daemonService) Lock(context.Context) {
	service.once.Do(func() {
		service.secrets.Lock()
		service.cancel()
	})
}

type outputRedactor struct{}

func (outputRedactor) Redact(input string, allowed map[policy.RedactionCategory]bool, maxBytes int) policy.RedactionResult {
	return policy.NewRedactor(allowed).WithMaxBytes(maxBytes).RedactString(input)
}

func defaultConfig() config.Config {
	return config.Config{
		Version: 1,
		Defaults: config.Defaults{
			ConnectTimeout: defaultConnectTimeout.String(), CommandTimeout: defaultCommandTimeout.String(),
			MaxOutputBytes: defaultMaxOutput, AuditFailClosed: true,
		},
		Servers: make(map[string]config.ServerPublic),
	}
}

func validateDefaults(defaults config.Defaults) (time.Duration, time.Duration, int64, error) {
	connect := defaultConnectTimeout
	if defaults.ConnectTimeout != "" {
		var err error
		connect, err = time.ParseDuration(defaults.ConnectTimeout)
		if err != nil || connect <= 0 || connect > 30*time.Minute {
			return 0, 0, 0, ErrStorage
		}
	}
	command := defaultCommandTimeout
	if defaults.CommandTimeout != "" {
		var err error
		command, err = time.ParseDuration(defaults.CommandTimeout)
		if err != nil || command <= 0 || command > 30*time.Minute {
			return 0, 0, 0, ErrStorage
		}
	}
	maxOutput := defaults.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = defaultMaxOutput
	}
	if maxOutput < 1 || maxOutput > 4<<20 {
		return 0, 0, 0, ErrStorage
	}
	return connect, command, maxOutput, nil
}

func publicServers(cfg config.Config, secrets *memorySecrets) []model.ServerSummary {
	servers := make([]model.ServerSummary, 0, len(cfg.Servers))
	for alias, public := range cfg.Servers {
		servers = append(servers, model.ServerSummary{Alias: alias, Description: public.Description, Available: secrets.Available(alias)})
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Alias < servers[j].Alias })
	return servers
}

func cloneVaultData(data vault.Data) vault.Data {
	cloned := vault.Data{Servers: make(map[string]vault.ServerSecret, len(data.Servers))}
	for alias, secret := range data.Servers {
		secret.Password = append([]byte(nil), secret.Password...)
		cloned.Servers[alias] = secret
	}
	return cloned
}

func cloneConfig(cfg config.Config) config.Config {
	cloned := cfg
	cloned.Servers = make(map[string]config.ServerPublic, len(cfg.Servers))
	for alias, public := range cfg.Servers {
		cloned.Servers[alias] = public
	}
	return cloned
}

func saveConfigVerified(path string, desired config.Config) error {
	if err := config.Save(path, desired); err == nil {
		return nil
	}
	actual, loadErr := config.Load(path)
	if loadErr == nil && reflect.DeepEqual(actual, desired) {
		return nil
	}
	return ErrStorage
}

func saveVaultVerified(store vault.Store, master []byte, desired vault.Data) error {
	if err := store.Save(master, desired); err == nil {
		return nil
	}
	actual, loadErr := store.Load(master)
	if loadErr != nil {
		return ErrStorage
	}
	defer zeroVaultData(&actual)
	if !reflect.DeepEqual(actual, desired) {
		return ErrStorage
	}
	return nil
}

func consistentAliases(cfg config.Config, data vault.Data) bool {
	if len(cfg.Servers) != len(data.Servers) {
		return false
	}
	for alias := range cfg.Servers {
		if _, ok := data.Servers[alias]; !ok {
			return false
		}
	}
	return true
}

func zeroVaultData(data *vault.Data) {
	if data == nil {
		return
	}
	for alias, secret := range data.Servers {
		vault.Zero(secret.Password)
		delete(data.Servers, alias)
	}
}

func validAlias(alias string) bool {
	if len(alias) == 0 || len(alias) > 64 {
		return false
	}
	for index, character := range alias {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-')
		if !valid {
			return false
		}
	}
	return true
}

func hasSecretArgument(args []string) bool {
	for _, argument := range args {
		if argument == "--" {
			break
		}
		name := strings.ToLower(strings.SplitN(argument, "=", 2)[0])
		switch name {
		case "--password", "--master-password", "--host", "--port", "--user", "--fingerprint", "--host-key":
			return true
		}
	}
	return false
}

func hasSecretEnvironment() bool {
	for _, name := range []string{"AEGIS_SSH_PASSWORD", "AEGIS_SSH_MASTER_PASSWORD", "AEGIS_SSH_HOST", "AEGIS_SSH_USER", "AEGIS_SSH_PORT"} {
		if _, present := os.LookupEnv(name); present {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
