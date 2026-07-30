package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/taotecode/aegis-ssh/internal/approval"
	"github.com/taotecode/aegis-ssh/internal/audit"
	"github.com/taotecode/aegis-ssh/internal/broker"
	"github.com/taotecode/aegis-ssh/internal/config"
	"github.com/taotecode/aegis-ssh/internal/mcpserver"
	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/opslog"
	"github.com/taotecode/aegis-ssh/internal/paths"
	"github.com/taotecode/aegis-ssh/internal/policy"
	"github.com/taotecode/aegis-ssh/internal/sshclient"
	"github.com/taotecode/aegis-ssh/internal/vault"
)

const (
	Version       = "0.3.0"
	PolicyVersion = "2"

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
	ErrInvalidAuthMethod  = errors.New("authentication method must be password or private-key")
	ErrPrivateKey         = errors.New("unable to load SSH private key")
	ErrServerExists       = errors.New("server alias already exists")
	ErrServerNotFound     = errors.New("server alias not found")
	ErrHostKeyProbe       = errors.New("unable to probe SSH host key")
	ErrHostKeyUnconfirmed = errors.New("SSH host key was not confirmed")
	ErrConnectionTest     = errors.New("SSH connection test failed")
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
	Root           string
	Stdout         io.Writer
	Stderr         io.Writer
	OpenTerminal   func() (Terminal, error)
	HostKeyProbe   HostKeyProbe
	ReadPrivateKey func(string) ([]byte, error)
	TestConnection func(context.Context, vault.ServerSecret) error
	BrokerClient   func(string) BrokerClient
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
	if deps.ReadPrivateKey == nil {
		deps.ReadPrivateKey = readPrivateKeyFile
	}
	if deps.TestConnection == nil {
		deps.TestConnection = testSSHConnection
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
		return application.daemon(ctx, true)
	case "daemon-locked":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.daemon(ctx, false)
	case "start":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.start(ctx)
	case "stop":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.stop(ctx)
	case "unlock":
		if len(args) != 1 {
			return ErrUsage
		}
		return application.unlock(ctx)
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
	case "config":
		return application.configCommand(ctx, args[1:])
	case "approval":
		return application.approvalCommand(ctx, args[1:])
	case "log":
		return application.logCommand(ctx, args[1:])
	case "service":
		return application.serviceCommand(ctx, args[1:])
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
	master, err := ReadSecret(terminal, application.text("Master password: ", "主密码："))
	if err != nil {
		return err
	}
	defer Zero(master)
	confirmation, err := ReadSecret(terminal, application.text("Confirm master password: ", "确认主密码："))
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
	_, _ = fmt.Fprintln(application.deps.Stdout, application.text("aegis-ssh initialized", "aegis-ssh 初始化完成"))
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
	case "show":
		if len(args) != 2 && (len(args) != 3 || args[2] != "--reveal") {
			return ErrUsage
		}
		return application.showServer(ctx, args[1], len(args) == 3)
	case "test":
		if len(args) != 2 {
			return ErrUsage
		}
		return application.testServer(ctx, args[1])
	default:
		return ErrUsage
	}
}

func (application *App) addServer(ctx context.Context) error {
	var addedAlias string
	err := application.withUnlockedVault(ctx, func(terminal Terminal, cfg *config.Config, data *vault.Data) error {
		alias, err := ReadText(terminal, application.text("Alias: ", "别名："))
		if err != nil || !validAlias(alias) {
			return ErrInvalidAlias
		}
		if _, ok := cfg.Servers[alias]; ok {
			return ErrServerExists
		}
		description, secret, err := application.readServer(ctx, terminal, "", nil)
		if err != nil {
			return err
		}
		cfg.Servers[alias] = publicServerConfig(description, secret)
		data.Servers[alias] = secret
		addedAlias = alias
		return nil
	})
	if err == nil {
		_, _ = fmt.Fprintf(application.deps.Stdout, application.text("server %s added\n", "服务器 %s 添加成功\n"), addedAlias)
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
		oldSecret, ok := data.Servers[alias]
		if !ok {
			return ErrServerNotFound
		}
		description, secret, err := application.readServer(ctx, terminal, cfg.Servers[alias].Description, &oldSecret)
		if err != nil {
			return err
		}
		old := data.Servers[alias]
		vault.ZeroServerSecret(&old)
		cfg.Servers[alias] = publicServerConfig(description, secret)
		data.Servers[alias] = secret
		return nil
	})
	if err == nil {
		_, _ = fmt.Fprintf(application.deps.Stdout, application.text("server %s updated\n", "服务器 %s 更新成功\n"), alias)
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
		confirmed, err := ConfirmExact(terminal, application.text("Type the alias to remove: ", "输入要删除的服务器别名："), alias)
		if err != nil {
			return err
		}
		if !confirmed {
			return ErrUsage
		}
		secret := data.Servers[alias]
		vault.ZeroServerSecret(&secret)
		delete(cfg.Servers, alias)
		delete(data.Servers, alias)
		return nil
	})
	if err == nil {
		_, _ = fmt.Fprintf(application.deps.Stdout, application.text("server %s removed\n", "服务器 %s 删除成功\n"), alias)
	}
	return err
}

func (application *App) readServer(ctx context.Context, terminal Terminal, existingDescription string, existing *vault.ServerSecret) (string, vault.ServerSecret, error) {
	lang := application.language()
	_, _ = fmt.Fprintln(terminal, localize(lang, "[1/6] Public description (optional)", "[1/6] 公开描述（可选）"))
	description, err := ReadTextDefault(terminal, localize(lang, "Description: ", "描述："), existingDescription)
	if err != nil {
		return "", vault.ServerSecret{}, err
	}
	_, _ = fmt.Fprintln(terminal, localize(lang, "[2/6] SSH network endpoint", "[2/6] SSH 网络端点"))
	hostDefault, userDefault, portDefault, authDefault := "", "", "22", "private-key"
	if existing != nil {
		hostDefault = existing.Host
		userDefault = existing.User
		portDefault = strconv.FormatUint(uint64(existing.Port), 10)
		authDefault = string(existing.EffectiveAuthMethod())
	}
	host, err := ReadTextDefault(terminal, localize(lang, "Host: ", "主机："), hostDefault)
	if err != nil || host == "" {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	portText, err := ReadTextDefault(terminal, localize(lang, "Port: ", "端口："), portDefault)
	if err != nil {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || portValue == 0 {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	_, _ = fmt.Fprintln(terminal, localize(lang, "[3/6] SSH login user", "[3/6] SSH 登录用户"))
	user, err := ReadTextDefault(terminal, localize(lang, "User: ", "用户名："), userDefault)
	if err != nil || user == "" {
		return "", vault.ServerSecret{}, ErrInvalidServer
	}
	_, _ = fmt.Fprintln(terminal, localize(lang, "[4/6] Authentication method", "[4/6] 认证方式"))
	authText, err := ReadTextDefault(terminal, localize(lang, "Authentication method (password/private-key): ", "认证方式（password/private-key）："), authDefault)
	method := vault.AuthMethod(authText)
	if err != nil || !validAuthMethod(method) {
		return "", vault.ServerSecret{}, ErrInvalidAuthMethod
	}
	fingerprint := ""
	if existing != nil && host == existing.Host && uint16(portValue) == existing.Port {
		fingerprint = existing.HostFingerprint
		_, _ = fmt.Fprintln(terminal, localize(lang, "[5/6] Host endpoint unchanged; preserving the pinned host key", "[5/6] 主机端点未变化，保留已固定的主机密钥"))
	} else {
		probeCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
		fingerprint, err = application.deps.HostKeyProbe.Probe(probeCtx, host, uint16(portValue))
		cancel()
		if err != nil || fingerprint == "" {
			return "", vault.ServerSecret{}, ErrHostKeyProbe
		}
		_, _ = fmt.Fprintf(terminal, localize(lang, "[5/6] Verify host identity through a trusted channel\nHost key fingerprint: %s\n", "[5/6] 请通过可信渠道核对主机身份\n主机密钥指纹：%s\n"), fingerprint)
		confirmed, confirmErr := ConfirmExact(terminal, localize(lang, "Type TRUST to pin this host key: ", "确认无误后输入 TRUST 固定主机密钥："), "TRUST")
		if confirmErr != nil {
			return "", vault.ServerSecret{}, confirmErr
		}
		if !confirmed {
			return "", vault.ServerSecret{}, ErrHostKeyUnconfirmed
		}
	}
	_, _ = fmt.Fprintln(terminal, localize(lang, "[6/6] Enter credentials securely; they will be imported into the encrypted vault", "[6/6] 安全输入凭据；凭据将导入加密 vault"))
	secret, err := application.readAuthenticationExisting(terminal, method, existing)
	if err != nil {
		return "", vault.ServerSecret{}, err
	}
	secret.Host = host
	secret.Port = uint16(portValue)
	secret.User = user
	secret.HostFingerprint = fingerprint
	_, _ = fmt.Fprintln(terminal, localize(lang, "Testing SSH authentication before saving...", "保存前正在测试 SSH 认证……"))
	if err := application.deps.TestConnection(ctx, secret); err != nil {
		vault.ZeroServerSecret(&secret)
		return "", vault.ServerSecret{}, ErrConnectionTest
	}
	return description, secret, nil
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
	cfg = normalizedConfig(cfg, nil)
	if cfg.Servers == nil {
		cfg.Servers = make(map[string]config.ServerPublic)
	}
	terminal, err := application.deps.OpenTerminal()
	if err != nil {
		return err
	}
	defer terminal.Close()
	master, err := ReadSecret(terminal, application.text("Master password: ", "主密码："))
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
	cfg = normalizedConfig(cfg, &data)
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

func (application *App) daemon(ctx context.Context, unlockAtStart bool) error {
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
	secrets := newMemorySecrets(vault.Data{Servers: make(map[string]vault.ServerSecret)})
	defer secrets.Lock()

	connectTimeout, commandTimeout, maxOutput, err := validateDefaults(cfg.Defaults)
	if err != nil {
		return ErrStorage
	}
	logger, err := audit.New(layout.AuditDir, audit.Options{Backups: 3})
	if err != nil {
		return ErrStorage
	}
	operations, err := opslog.New(layout.LogsDir, cfg.Defaults.LogLevel)
	if err != nil {
		return ErrStorage
	}
	operations.Write(opslog.Info, "daemon", "started", "", "", "", 0)
	redactor := outputRedactor{}
	sshExecutor := sshclient.NewWithConnectTimeout(connectTimeout)
	service, err := broker.NewService(broker.ServiceOptions{
		Secrets: secrets, Analyzer: policy.NewAnalyzer(),
		Approvals: approval.NewStore(time.Now, rand.Reader), Executor: sshExecutor,
		Redactor: redactor, Auditor: logger, Now: time.Now,
		AllowAuditFailOpen: !cfg.Defaults.AuditFailClosed,
		DefaultTimeout:     commandTimeout, DefaultMaxOutput: maxOutput,
		Servers: publicServers(cfg, secrets), VaultLocked: true, Version: Version, PolicyVersion: PolicyVersion,
		RiskPolicy: cfg.Defaults.RiskPolicy, LogLevel: cfg.Defaults.LogLevel, BatchConcurrency: cfg.Defaults.BatchConcurrency,
		NotifyApproval: notifyLocalApproval,
	})
	if err != nil {
		return ErrStorage
	}
	daemonCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	wrapped := &daemonService{Service: service, secrets: secrets, cancel: cancel, operations: operations, connections: sshExecutor, lockedServers: publicServers(cfg, secrets)}
	wrapped.configure = func(key, value string) error {
		latest, loadErr := config.Load(layout.ConfigFile)
		if loadErr != nil {
			return model.ErrValidation
		}
		switch key {
		case "language":
			if value != "auto" && value != "en" && value != "zh-CN" {
				return model.ErrValidation
			}
			latest.Language = value
		case "risk-policy":
			if value != "enforce" && value != "warn" && value != "off" {
				return model.ErrValidation
			}
			latest.Defaults.RiskPolicy = value
		case "log-level":
			if _, ok := opslog.ParseLevel(value); !ok {
				return model.ErrValidation
			}
			latest.Defaults.LogLevel = value
		case "batch-concurrency":
			number, parseErr := strconv.Atoi(value)
			if parseErr != nil || number < 1 || number > 32 {
				return model.ErrValidation
			}
			latest.Defaults.BatchConcurrency = number
		default:
			return model.ErrValidation
		}
		if saveErr := saveConfigVerified(layout.ConfigFile, latest); saveErr != nil {
			return model.ErrAudit
		}
		if key == "log-level" {
			operations.SetLevel(value)
		}
		service.UpdateSettings(latest.Defaults.RiskPolicy, latest.Defaults.LogLevel, latest.Defaults.BatchConcurrency)
		operations.Write(opslog.Info, "config", "updated", "", "", "", 0)
		return nil
	}
	wrapped.unlock = func(master []byte) error {
		data, loadErr := (vault.Store{Path: layout.VaultFile}).Load(master)
		if loadErr != nil {
			return model.ErrLockedVault
		}
		defer zeroVaultData(&data)
		latest, configErr := config.Load(layout.ConfigFile)
		if configErr != nil || !consistentAliases(latest, data) {
			return model.ErrLockedVault
		}
		latest = normalizedConfig(latest, &data)
		if saveErr := saveConfigVerified(layout.ConfigFile, latest); saveErr != nil {
			return model.ErrAudit
		}
		wrapped.mu.Lock()
		wrapped.lockedServers = publicServers(latest, &memorySecrets{servers: map[string]vault.ServerSecret{}})
		wrapped.mu.Unlock()
		secrets.Replace(data)
		service.SetVaultState(false, publicServers(latest, secrets))
		operations.Write(opslog.Info, "vault", "unlocked", "", "", "", 0)
		return nil
	}
	if unlockAtStart {
		terminal, openErr := application.deps.OpenTerminal()
		if openErr != nil {
			return openErr
		}
		master, readErr := ReadSecret(terminal, application.text("Master password: ", "主密码："))
		_ = terminal.Close()
		if readErr != nil {
			return readErr
		}
		defer Zero(master)
		if unlockErr := wrapped.Unlock(ctx, master); unlockErr != nil {
			return ErrStorage
		}
	}
	if err := broker.NewServer(layout.SocketFile, wrapped).Serve(daemonCtx); err != nil {
		return err
	}
	return nil
}

func (application *App) start(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	if running, _ := application.daemonReachable(ctx, layout.SocketFile); running {
		_, _ = fmt.Fprintln(application.deps.Stdout, application.text("aegis-ssh daemon already running", "aegis-ssh 后台服务已在运行"))
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return ErrStorage
	}
	logPath := filepath.Join(layout.RunDir, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return ErrStorage
	}
	command := exec.Command(executable, "daemon-locked")
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	_ = logFile.Close()
	_ = command.Process.Release()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if running, _ := application.daemonReachable(ctx, layout.SocketFile); running {
			_, _ = fmt.Fprintln(application.deps.Stdout, application.text("aegis-ssh daemon started (locked)", "aegis-ssh 后台服务已启动（锁定状态）"))
			return application.unlock(ctx)
		}
		time.Sleep(25 * time.Millisecond)
	}
	return ErrDaemonUnavailable
}

func (application *App) stop(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	client := application.deps.BrokerClient(layout.SocketFile)
	stopper, ok := client.(interface{ Stop(context.Context) error })
	if !ok {
		return ErrDaemonUnavailable
	}
	if err := stopper.Stop(ctx); err != nil {
		return ErrDaemonUnavailable
	}
	_, _ = fmt.Fprintln(application.deps.Stdout, application.text("aegis-ssh daemon stopped", "aegis-ssh 后台服务已停止"))
	return nil
}

func (application *App) unlock(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	terminal, err := application.deps.OpenTerminal()
	if err != nil {
		return err
	}
	defer terminal.Close()
	master, err := ReadSecret(terminal, application.text("Master password: ", "主密码："))
	if err != nil {
		return err
	}
	defer Zero(master)
	client := application.deps.BrokerClient(layout.SocketFile)
	unlocker, ok := client.(interface {
		Unlock(context.Context, []byte) error
	})
	if !ok {
		return ErrDaemonUnavailable
	}
	if err := unlocker.Unlock(ctx, master); err != nil {
		return ErrStorage
	}
	_, _ = fmt.Fprintln(application.deps.Stdout, application.text("aegis-ssh daemon unlocked", "aegis-ssh 后台服务已解锁"))
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
	_, _ = fmt.Fprintln(application.deps.Stdout, application.text("aegis-ssh daemon locked and credentials cleared", "aegis-ssh 已锁定并清除内存凭据"))
	return nil
}

func (application *App) status(ctx context.Context) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	status, err := application.deps.BrokerClient(layout.SocketFile).Status(ctx)
	if err != nil {
		_, _ = fmt.Fprintln(application.deps.Stdout, application.text("daemon: unavailable", "后台服务：未运行"))
		application.printServiceStatus()
		return nil
	}
	state := application.text("ready", "就绪")
	if status.VaultLocked {
		state = application.text("locked", "已锁定")
	}
	format := application.text("daemon: %s\npid: %d\nstarted: %s\nversion: %s\npolicy: %s\nrisk policy: %s\nlog level: %s\nbatch concurrency: %d\nservers: %d\n", "后台服务：%s\n进程 ID：%d\n启动时间：%s\n版本：%s\n策略版本：%s\n风险策略：%s\n日志级别：%s\n批量并发：%d\n服务器数量：%d\n")
	_, _ = fmt.Fprintf(application.deps.Stdout, format, state, status.PID, status.StartedAt, status.Version, status.PolicyVersion, defaultString(status.RiskPolicy, "enforce"), defaultString(status.LogLevel, "info"), defaultInt(status.BatchConcurrency, 8), status.ServerCount)
	application.printServiceStatus()
	return nil
}

func (application *App) execute(ctx context.Context, args []string) error {
	if len(args) < 3 {
		return ErrUsage
	}
	if args[0] == "--servers" || args[0] == "--all" {
		return application.executeBatch(ctx, args)
	}
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
		confirmed, confirmErr := ConfirmExact(terminal, application.text("Type the approval code to continue: ", "输入批准码继续："), result.Approval.Code)
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

func (application *App) executeBatch(ctx context.Context, args []string) error {
	request := model.BatchExecuteRequest{}
	switch {
	case len(args) == 4 && args[0] == "--servers" && args[2] == "--":
		request.ServerAliases = strings.Split(args[1], ",")
		request.Command = args[3]
	case len(args) == 3 && args[0] == "--all" && args[1] == "--":
		request.All = true
		request.Command = args[2]
	default:
		return ErrUsage
	}
	for _, alias := range request.ServerAliases {
		if !validAlias(strings.TrimSpace(alias)) {
			return ErrInvalidAlias
		}
	}
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	client := application.deps.BrokerClient(layout.SocketFile)
	batch, ok := client.(interface {
		ExecuteBatch(context.Context, model.BatchExecuteRequest) (model.BatchExecuteResult, error)
	})
	if !ok {
		return ErrDaemonUnavailable
	}
	result, err := batch.ExecuteBatch(ctx, request)
	if err != nil {
		return ErrDaemonUnavailable
	}
	if result.Status == model.StatusRequiresApproval {
		return model.ErrApproval
	}
	failed := false
	for _, one := range result.Results {
		_, _ = fmt.Fprintf(application.deps.Stdout, "== %s ==\n", one.ServerAlias)
		if err := application.printExecuteResult(one.ExecuteResult); err != nil {
			failed = true
			_, _ = fmt.Fprintf(application.deps.Stderr, "[%s] %v\n", one.ServerAlias, err)
		}
	}
	if failed {
		return model.ErrConnection
	}
	return nil
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
	lang := application.language()
	english := `Usage: aegis-ssh <command>

Commands:
  init                         Initialize encrypted local storage
  daemon                       Unlock and run the SSH broker
  start                        Start the broker in the background and unlock it
  unlock                       Unlock a running broker
  lock                         Clear in-memory credentials but keep broker running
  stop                         Stop the background broker
  status                       Show broker availability
  config show|set              Show or change safe settings
  approval list|show|approve|deny  Manage local approvals
  server add                   Add a server interactively
  server edit <alias>          Replace a server interactively
  server remove <alias>        Remove a server
  server list                  List public aliases and descriptions
  server show <alias>          Show masked connection details
  server test <alias>          Test SSH authentication
  exec <alias> -- '<command>'  Execute an exact remote shell string
  exec --servers a,b -- '<command>' Execute concurrently
  exec --all -- '<command>'    Execute on all configured aliases
	service install|uninstall    Manage the login service
	log path|show|follow         Inspect operational logs
  mcp                          Run the standard stdio MCP server
`
	chinese := `用法：aegis-ssh <命令>

命令：
  init                         初始化加密存储
  daemon                       前台解锁并运行 SSH broker
  start / stop                 后台启动 / 停止 broker
  unlock / lock                解锁 / 清除内存凭据
  status                       查看运行状态
  config show|set              查看或修改语言、风险和日志配置
  approval list|show|approve|deny  在本机处理风险审批
  server add|edit|remove       管理服务器
  server list|show|test        列出、查看或测试服务器
  exec <别名> -- '<命令>'       执行远程命令
  exec --servers a,b -- '<命令>'  并发批量执行
  exec --all -- '<命令>'       在全部别名上并发执行
  service install|uninstall    管理登录自启服务
  log path|show|follow         查看或持续跟踪运维日志
  mcp                          启动标准 MCP 服务
`
	_, _ = io.WriteString(application.deps.Stdout, localize(lang, english, chinese))
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

func (secrets *memorySecrets) Replace(data vault.Data) {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	for alias, secret := range secrets.servers {
		vault.ZeroServerSecret(&secret)
		delete(secrets.servers, alias)
	}
	for alias, secret := range data.Servers {
		secrets.servers[alias] = vault.CloneServerSecret(secret)
	}
}

func newMemorySecrets(data vault.Data) *memorySecrets {
	return &memorySecrets{servers: cloneVaultData(data).Servers}
}

func (secrets *memorySecrets) Lookup(alias string) (vault.ServerSecret, bool) {
	secrets.mu.RLock()
	defer secrets.mu.RUnlock()
	secret, ok := secrets.servers[alias]
	return vault.CloneServerSecret(secret), ok
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
		vault.ZeroServerSecret(&secret)
		delete(secrets.servers, alias)
	}
}

type daemonService struct {
	*broker.Service
	secrets       *memorySecrets
	cancel        context.CancelFunc
	once          sync.Once
	unlock        func([]byte) error
	operations    *opslog.Logger
	connections   *sshclient.Client
	configure     func(string, string) error
	lockedServers []model.ServerSummary
	mu            sync.Mutex
}

func (service *daemonService) Lock(context.Context) {
	service.secrets.Lock()
	service.connections.Close()
	service.mu.Lock()
	locked := append([]model.ServerSummary(nil), service.lockedServers...)
	service.mu.Unlock()
	service.Service.SetVaultState(true, locked)
	service.operations.Write(opslog.Info, "vault", "locked", "", "", "", 0)
}

func (service *daemonService) Stop(context.Context) {
	service.once.Do(func() {
		service.secrets.Lock()
		service.connections.Close()
		service.operations.Write(opslog.Info, "daemon", "stopped", "", "", "", 0)
		service.cancel()
	})
}
func (service *daemonService) Unlock(_ context.Context, master []byte) error {
	if service.unlock == nil {
		return model.ErrValidation
	}
	return service.unlock(master)
}

func (service *daemonService) ListApprovalSummaries(includeCommand bool) []model.ApprovalSummary {
	items := service.Service.ListApprovals(includeCommand)
	result := make([]model.ApprovalSummary, 0, len(items))
	for _, item := range items {
		aliases := item.ServerAliases
		if len(aliases) == 0 && item.ServerAlias != "" {
			aliases = []string{item.ServerAlias}
		}
		categories := make([]string, len(item.Categories))
		for index, category := range item.Categories {
			categories[index] = string(category)
		}
		result = append(result, model.ApprovalSummary{ID: item.ID, ServerAliases: aliases, Categories: categories, Command: string(item.Command), CreatedAt: item.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: item.ExpiresAt.UTC().Format(time.RFC3339), State: "pending"})
	}
	return result
}
func (service *daemonService) DecideApproval(id string, allow bool) error {
	return service.Service.DecideApproval(id, allow)
}
func (service *daemonService) Configure(_ context.Context, key, value string) error {
	if service.configure == nil {
		return model.ErrValidation
	}
	return service.configure(key, value)
}

type outputRedactor struct{}

func (outputRedactor) Redact(input string, allowed map[policy.RedactionCategory]bool, maxBytes int) policy.RedactionResult {
	return policy.NewRedactor(allowed).WithMaxBytes(maxBytes).RedactString(input)
}

func defaultConfig() config.Config {
	return config.Config{
		Version: 2, Language: "auto",
		Defaults: config.Defaults{
			ConnectTimeout: defaultConnectTimeout.String(), CommandTimeout: defaultCommandTimeout.String(),
			MaxOutputBytes: defaultMaxOutput, AuditFailClosed: true, RiskPolicy: "enforce", LogLevel: "info", BatchConcurrency: 8,
		},
		Servers: make(map[string]config.ServerPublic),
	}
}

func normalizedConfig(cfg config.Config, data *vault.Data) config.Config {
	cfg.Version = 2
	if cfg.Language == "" {
		cfg.Language = "auto"
	}
	if cfg.Defaults.RiskPolicy == "" {
		cfg.Defaults.RiskPolicy = "enforce"
	}
	if cfg.Defaults.LogLevel == "" {
		cfg.Defaults.LogLevel = "info"
	}
	if cfg.Defaults.BatchConcurrency == 0 {
		cfg.Defaults.BatchConcurrency = 8
	}
	if cfg.Servers == nil {
		cfg.Servers = make(map[string]config.ServerPublic)
	}
	if data != nil {
		for alias, secret := range data.Servers {
			public := cfg.Servers[alias]
			cfg.Servers[alias] = publicServerConfig(public.Description, secret)
		}
	}
	return cfg
}

func publicServerConfig(description string, secret vault.ServerSecret) config.ServerPublic {
	return config.ServerPublic{Description: description, HostHint: maskValue(secret.Host), Port: secret.Port, UserHint: maskValue(secret.User), AuthMethod: string(secret.EffectiveAuthMethod()), FingerprintHint: maskFingerprint(secret.HostFingerprint)}
}
func maskValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 2 {
		return strings.Repeat("*", len(value))
	}
	return value[:1] + strings.Repeat("*", min(8, len(value)-2)) + value[len(value)-1:]
}
func maskFingerprint(value string) string {
	if len(value) <= 12 {
		return maskValue(value)
	}
	return value[:7] + "..." + value[len(value)-5:]
}

func notifyLocalApproval() {
	message := "A command is waiting. Run: aegis-ssh approval list"
	var command *exec.Cmd
	if runtime.GOOS == "darwin" {
		command = exec.Command("osascript", "-e", `display notification "`+message+`" with title "Aegis SSH approval"`)
	}
	if runtime.GOOS == "linux" {
		command = exec.Command("notify-send", "Aegis SSH approval", message)
	}
	if command != nil {
		if err := command.Start(); err == nil {
			go func() { _ = command.Wait() }()
		}
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
		cloned.Servers[alias] = vault.CloneServerSecret(secret)
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
		vault.ZeroServerSecret(&secret)
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
		case "--password", "--master-password", "--host", "--port", "--user", "--fingerprint", "--host-key",
			"--private-key", "--identity-file", "--private-key-passphrase":
			return true
		}
	}
	return false
}

func hasSecretEnvironment() bool {
	for _, name := range []string{
		"AEGIS_SSH_PASSWORD", "AEGIS_SSH_MASTER_PASSWORD", "AEGIS_SSH_HOST", "AEGIS_SSH_USER", "AEGIS_SSH_PORT",
		"AEGIS_SSH_PRIVATE_KEY", "AEGIS_SSH_PRIVATE_KEY_PASSPHRASE",
	} {
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
