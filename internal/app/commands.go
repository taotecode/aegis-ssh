package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/taotecode/aegis-ssh/internal/config"
	"github.com/taotecode/aegis-ssh/internal/model"
	"github.com/taotecode/aegis-ssh/internal/sshclient"
	"github.com/taotecode/aegis-ssh/internal/vault"
)

func (application *App) showServer(ctx context.Context, alias string, reveal bool) error {
	if !validAlias(alias) {
		return ErrInvalidAlias
	}
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	cfg, err := config.Load(layout.ConfigFile)
	if err != nil {
		return ErrNotInitialized
	}
	server, ok := cfg.Servers[alias]
	if !ok {
		return ErrServerNotFound
	}
	if reveal {
		return application.withReadOnlyVault(ctx, func(_ Terminal, _ config.Config, data vault.Data) error {
			secret, ok := data.Servers[alias]
			if !ok {
				return ErrServerNotFound
			}
			format := application.text("alias: %s\ndescription: %s\nhost: %s\nport: %d\nuser: %s\nauthentication: %s\nhost key: %s\n", "别名：%s\n描述：%s\n主机：%s\n端口：%d\n用户：%s\n认证方式：%s\n主机密钥：%s\n")
			_, _ = fmt.Fprintf(application.deps.Stdout, format, alias, server.Description, secret.Host, secret.Port, secret.User, secret.EffectiveAuthMethod(), secret.HostFingerprint)
			return nil
		})
	}
	format := application.text("alias: %s\ndescription: %s\nhost: %s\nport: %d\nuser: %s\nauthentication: %s\nhost key: %s\n", "别名：%s\n描述：%s\n主机：%s\n端口：%d\n用户：%s\n认证方式：%s\n主机密钥：%s\n")
	_, _ = fmt.Fprintf(application.deps.Stdout, format, alias, server.Description, server.HostHint, server.Port, server.UserHint, server.AuthMethod, server.FingerprintHint)
	return nil
}

func (application *App) testServer(ctx context.Context, alias string) error {
	if !validAlias(alias) {
		return ErrInvalidAlias
	}
	return application.withReadOnlyVault(ctx, func(_ Terminal, cfg config.Config, data vault.Data) error {
		secret, ok := data.Servers[alias]
		if !ok {
			return ErrServerNotFound
		}
		connect, _, _, err := validateDefaults(cfg.Defaults)
		if err != nil {
			return ErrStorage
		}
		result, err := sshclient.NewWithConnectTimeout(connect).Execute(ctx, secret, "true", sshclient.Limits{Timeout: connect, MaxOutputBytes: 1024})
		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			return &ExitCodeError{Code: result.ExitCode}
		}
		_, _ = fmt.Fprintf(application.deps.Stdout, application.text("server %s connection succeeded\n", "服务器 %s 连接测试成功\n"), alias)
		return nil
	})
}

func testSSHConnection(ctx context.Context, secret vault.ServerSecret) error {
	result, err := sshclient.NewWithConnectTimeout(defaultConnectTimeout).Execute(ctx, secret, "true", sshclient.Limits{Timeout: defaultConnectTimeout, MaxOutputBytes: 1024})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return &ExitCodeError{Code: result.ExitCode}
	}
	return nil
}

func (application *App) withReadOnlyVault(ctx context.Context, operation func(Terminal, config.Config, vault.Data) error) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	cfg, err := config.Load(layout.ConfigFile)
	if err != nil {
		return ErrNotInitialized
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
	data, err := (vault.Store{Path: layout.VaultFile}).Load(master)
	if err != nil {
		return ErrStorage
	}
	defer zeroVaultData(&data)
	return operation(terminal, cfg, data)
}

func (application *App) approvalCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return ErrUsage
	}
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	client := application.deps.BrokerClient(layout.SocketFile)
	manager, ok := client.(interface {
		ListApprovals(context.Context, bool) ([]model.ApprovalSummary, error)
		DecideApproval(context.Context, string, bool) error
	})
	if !ok {
		return ErrDaemonUnavailable
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return ErrUsage
		}
		items, err := manager.ListApprovals(ctx, false)
		if err != nil {
			return ErrDaemonUnavailable
		}
		for _, item := range items {
			_, _ = fmt.Fprintf(application.deps.Stdout, "%s\t%s\t%s\n", item.ID, strings.Join(item.ServerAliases, ","), strings.Join(item.Categories, ","))
		}
		return nil
	case "show":
		if len(args) != 2 {
			return ErrUsage
		}
		items, err := manager.ListApprovals(ctx, true)
		if err != nil {
			return ErrDaemonUnavailable
		}
		for _, item := range items {
			if item.ID == args[1] {
				_, _ = fmt.Fprintf(application.deps.Stdout, "id: %s\nservers: %s\nrisks: %s\ncommand: %s\nexpires: %s\n", item.ID, strings.Join(item.ServerAliases, ","), strings.Join(item.Categories, ","), item.Command, item.ExpiresAt)
				return nil
			}
		}
		return model.ErrApproval
	case "approve", "deny":
		if len(args) != 2 {
			return ErrUsage
		}
		if err := manager.DecideApproval(ctx, args[1], args[0] == "approve"); err != nil {
			return model.ErrApproval
		}
		decision := application.text("denied", "已拒绝")
		if args[0] == "approve" {
			decision = application.text("approved", "已允许")
		}
		_, _ = fmt.Fprintf(application.deps.Stdout, application.text("approval %s %s\n", "审批 %s %s\n"), args[1], decision)
		return nil
	}
	return ErrUsage
}

func (application *App) configCommand(ctx context.Context, args []string) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	cfg, err := config.Load(layout.ConfigFile)
	if err != nil {
		return ErrNotInitialized
	}
	if len(args) == 1 && args[0] == "show" {
		format := application.text("language: %s\nrisk_policy: %s\nlog_level: %s\nbatch_concurrency: %d\n", "语言：%s\n风险策略：%s\n日志级别：%s\n批量并发：%d\n")
		_, _ = fmt.Fprintf(application.deps.Stdout, format, defaultString(cfg.Language, "auto"), defaultString(cfg.Defaults.RiskPolicy, "enforce"), defaultString(cfg.Defaults.LogLevel, "info"), defaultInt(cfg.Defaults.BatchConcurrency, 8))
		return nil
	}
	if len(args) != 3 || args[0] != "set" {
		return ErrUsage
	}
	key, value := args[1], args[2]
	switch key {
	case "language":
		if value != "auto" && value != "en" && value != "zh-CN" {
			return ErrUsage
		}
		cfg.Language = value
	case "risk-policy":
		if value != "enforce" && value != "warn" && value != "off" {
			return ErrUsage
		}
		cfg.Defaults.RiskPolicy = value
	case "log-level":
		if value != "debug" && value != "info" && value != "warn" && value != "error" && value != "off" {
			return ErrUsage
		}
		cfg.Defaults.LogLevel = value
	case "batch-concurrency":
		number, parseErr := strconv.Atoi(value)
		if parseErr != nil || number < 1 || number > 32 {
			return ErrUsage
		}
		cfg.Defaults.BatchConcurrency = number
	default:
		return ErrUsage
	}
	if running, _ := application.daemonReachable(ctx, layout.SocketFile); running {
		client := application.deps.BrokerClient(layout.SocketFile)
		updater, ok := client.(interface {
			Configure(context.Context, string, string) error
		})
		if !ok {
			return ErrDaemonRunning
		}
		if err := updater.Configure(ctx, key, value); err != nil {
			return ErrStorage
		}
		_, _ = fmt.Fprintln(application.deps.Stdout, application.text("configuration updated", "配置已更新"))
		return nil
	}
	if err := saveConfigVerified(layout.ConfigFile, cfg); err != nil {
		return ErrStorage
	}
	_, _ = fmt.Fprintln(application.deps.Stdout, application.text("configuration updated", "配置已更新"))
	return nil
}

func (application *App) logCommand(ctx context.Context, args []string) error {
	layout, err := application.layout()
	if err != nil {
		return ErrStorage
	}
	path := filepath.Join(layout.Root, "logs", "aegis.log")
	if len(args) == 1 && args[0] == "path" {
		_, _ = fmt.Fprintln(application.deps.Stdout, path)
		return nil
	}
	if len(args) == 1 && args[0] == "show" {
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return ErrStorage
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			_, _ = fmt.Fprintln(application.deps.Stdout, scanner.Text())
		}
		return scanner.Err()
	}
	if len(args) == 1 && args[0] == "follow" {
		command := exec.CommandContext(ctx, "tail", "-n", "50", "-F", path)
		command.Stdout = application.deps.Stdout
		command.Stderr = application.deps.Stderr
		if err := command.Run(); err != nil && ctx.Err() == nil {
			return ErrStorage
		}
		return ctx.Err()
	}
	return ErrUsage
}

func (application *App) printServiceStatus() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	installed, loaded := false, false
	switch runtime.GOOS {
	case "darwin":
		path := filepath.Join(home, "Library", "LaunchAgents", "com.taotecode.aegis-ssh.plist")
		installed = exists(path)
		loaded = exec.Command("launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/com.taotecode.aegis-ssh").Run() == nil
	case "linux":
		path := filepath.Join(home, ".config", "systemd", "user", "aegis-ssh.service")
		installed = exists(path)
		loaded = exec.Command("systemctl", "--user", "is-enabled", "--quiet", "aegis-ssh.service").Run() == nil
	default:
		return
	}
	state := application.text("not installed", "未安装")
	if installed {
		state = application.text("installed", "已安装")
	}
	if loaded {
		state = application.text("installed and enabled", "已安装并启用")
	}
	_, _ = fmt.Fprintf(application.deps.Stdout, application.text("login service: %s\n", "登录自启服务：%s\n"), state)
}

func (application *App) serviceCommand(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return ErrUsage
	}
	switch args[0] {
	case "install":
		return application.installService()
	case "uninstall":
		return application.uninstallService()
	case "start":
		return application.start(ctx)
	case "stop":
		return application.stop(ctx)
	case "status":
		return application.status(ctx)
	}
	return ErrUsage
}

func (application *App) installService() error {
	executable, err := os.Executable()
	if err != nil {
		return ErrStorage
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ErrStorage
	}
	if runtime.GOOS == "darwin" {
		dir := filepath.Join(home, "Library", "LaunchAgents")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return ErrStorage
		}
		path := filepath.Join(dir, "com.taotecode.aegis-ssh.plist")
		content := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>com.taotecode.aegis-ssh</string><key>ProgramArguments</key><array><string>%s</string><string>daemon-locked</string></array><key>RunAtLoad</key><true/></dict></plist>\n", html.EscapeString(executable))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return ErrStorage
		}
		_ = exec.Command("launchctl", "bootstrap", "gui/"+strconv.Itoa(os.Getuid()), path).Run()
		_, _ = fmt.Fprintln(application.deps.Stdout, application.text("launchd user service installed", "launchd 用户服务安装完成"))
		return nil
	}
	if runtime.GOOS == "linux" {
		dir := filepath.Join(home, ".config", "systemd", "user")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return ErrStorage
		}
		path := filepath.Join(dir, "aegis-ssh.service")
		content := fmt.Sprintf("[Unit]\nDescription=Aegis SSH Broker\n[Service]\nExecStart=%s daemon-locked\nRestart=on-failure\n[Install]\nWantedBy=default.target\n", strconv.Quote(executable))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return ErrStorage
		}
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		_ = exec.Command("systemctl", "--user", "enable", "--now", "aegis-ssh.service").Run()
		_, _ = fmt.Fprintln(application.deps.Stdout, application.text("systemd user service installed", "systemd 用户服务安装完成"))
		return nil
	}
	return errors.New("user services are unsupported on this platform")
}
func (application *App) uninstallService() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return ErrStorage
	}
	var path string
	if runtime.GOOS == "darwin" {
		path = filepath.Join(home, "Library", "LaunchAgents", "com.taotecode.aegis-ssh.plist")
		_ = exec.Command("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid()), path).Run()
	} else {
		path = filepath.Join(home, ".config", "systemd", "user", "aegis-ssh.service")
		_ = exec.Command("systemctl", "--user", "disable", "--now", "aegis-ssh.service").Run()
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrStorage
	}
	_, _ = fmt.Fprintln(application.deps.Stdout, application.text("user service uninstalled", "用户服务已卸载"))
	return nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}
