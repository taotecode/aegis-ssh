package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	embeddedskills "github.com/taotecode/aegis-ssh/skills"
)

var ErrAgentConfig = errors.New("one or more agent operations failed")

type agentOutcome string

const (
	agentConfigured agentOutcome = "configured"
	agentSkipped    agentOutcome = "skipped"
	agentFailed     agentOutcome = "failed"
)

type agentStep struct {
	client  string
	outcome agentOutcome
	detail  string
}

type agentState struct {
	client     string
	installed  bool
	configured string
	path       string
}

type agentClient interface {
	id() string
	detect() bool
	configure(context.Context, string) agentStep
	unconfigure(context.Context) agentStep
	inspect(context.Context, string) agentState
}

type cliAgent struct {
	name, command, configPath, skillRoot string
	inspectArgs, addPrefix, removeArgs   []string
}

func (client cliAgent) id() string { return client.name }

func (client cliAgent) detect() bool {
	_, err := exec.LookPath(client.command)
	return err == nil || client.configPath != "" && exists(client.configPath)
}

func (client cliAgent) inspect(ctx context.Context, binPath string) agentState {
	state := agentState{client: client.id(), installed: client.detect(), configured: "no", path: "-"}
	if _, err := exec.LookPath(client.command); err != nil {
		state.configured = "unknown"
		state.path = "client CLI unavailable"
		return state
	}
	stdout, stderr, err := runAgentClient(ctx, client.command, client.inspectArgs...)
	output := stdout + "\n" + stderr
	if err != nil || !strings.Contains(output, "aegis-ssh") {
		return state
	}
	state.path = configuredCommand(output)
	if binPath != "" && strings.Contains(output, binPath) && hasMCPArgument(output, binPath) {
		state.configured = "yes"
		state.path = binPath
	} else {
		state.configured = "stale"
	}
	return state
}

func (client cliAgent) configure(ctx context.Context, binPath string) agentStep {
	if _, err := exec.LookPath(client.command); err != nil {
		return agentStep{client.id(), agentFailed, client.command + " CLI not found"}
	}
	state := client.inspect(ctx, binPath)
	changed := false
	if state.configured != "yes" {
		if state.configured == "stale" {
			if _, stderr, err := runAgentClient(ctx, client.command, client.removeArgs...); err != nil {
				return agentStep{client.id(), agentFailed, firstAgentError(stderr, err)}
			}
		}
		args := append(append([]string(nil), client.addPrefix...), binPath, "mcp")
		if _, stderr, err := runAgentClient(ctx, client.command, args...); err != nil {
			return agentStep{client.id(), agentFailed, firstAgentError(stderr, err)}
		}
		changed = true
	}
	if client.skillRoot != "" {
		skillChanged, err := materializeSkill(client.skillRoot)
		if err != nil {
			return agentStep{client.id(), agentFailed, err.Error()}
		}
		changed = changed || skillChanged
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "Aegis SSH integration installed"}
	}
	return agentStep{client.id(), agentSkipped, "already configured"}
}

func (client cliAgent) unconfigure(ctx context.Context) agentStep {
	changed := false
	_, cliErr := exec.LookPath(client.command)
	if cliErr == nil {
		state := client.inspect(ctx, "")
		if state.configured == "stale" || state.configured == "yes" {
			if _, stderr, err := runAgentClient(ctx, client.command, client.removeArgs...); err != nil {
				return agentStep{client.id(), agentFailed, firstAgentError(stderr, err)}
			}
			changed = true
		}
	}
	if client.skillRoot != "" {
		skillChanged, err := removeManagedSkill(client.skillRoot)
		if err != nil {
			return agentStep{client.id(), agentFailed, err.Error()}
		}
		changed = changed || skillChanged
	}
	if cliErr != nil && client.configPath != "" && exists(client.configPath) {
		return agentStep{client.id(), agentFailed, client.command + " CLI not found; MCP entry was not removed"}
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "Aegis SSH integration removed"}
	}
	return agentStep{client.id(), agentSkipped, "not configured"}
}

type cursorAgent struct{ home string }

func (client cursorAgent) id() string   { return "cursor" }
func (client cursorAgent) path() string { return filepath.Join(client.home, ".cursor", "mcp.json") }
func (client cursorAgent) detect() bool { return exists(filepath.Join(client.home, ".cursor")) }

func (client cursorAgent) configure(_ context.Context, binPath string) agentStep {
	changed, err := upsertJSONServer(client.path(), "mcpServers", binPath)
	if err != nil {
		return agentStep{client.id(), agentFailed, err.Error()}
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "MCP server configured"}
	}
	return agentStep{client.id(), agentSkipped, "already configured"}
}

func (client cursorAgent) unconfigure(context.Context) agentStep {
	changed, err := removeJSONServer(client.path(), "mcpServers")
	if err != nil {
		return agentStep{client.id(), agentFailed, err.Error()}
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "MCP server removed"}
	}
	return agentStep{client.id(), agentSkipped, "not configured"}
}

func (client cursorAgent) inspect(_ context.Context, binPath string) agentState {
	configured, path, err := inspectJSONServer(client.path(), "mcpServers", binPath)
	state := agentState{client.id(), client.detect(), configured, path}
	if err != nil {
		state.configured, state.path = "unknown", err.Error()
	}
	return state
}

type vscodeAgent struct{ home string }

func (client vscodeAgent) id() string   { return "vscode" }
func (client vscodeAgent) detect() bool { _, err := exec.LookPath("code"); return err == nil }
func (client vscodeAgent) path() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(client.home, "Library", "Application Support", "Code", "User", "mcp.json")
	}
	configRoot := os.Getenv("XDG_CONFIG_HOME")
	if configRoot == "" {
		configRoot = filepath.Join(client.home, ".config")
	}
	return filepath.Join(configRoot, "Code", "User", "mcp.json")
}

func (client vscodeAgent) configure(ctx context.Context, binPath string) agentStep {
	if _, err := exec.LookPath("code"); err != nil {
		return agentStep{client.id(), agentFailed, "code CLI not found"}
	}
	if state := client.inspect(ctx, binPath); state.configured == "yes" {
		return agentStep{client.id(), agentSkipped, "already configured"}
	}
	payload, _ := json.Marshal(map[string]any{"name": "aegis-ssh", "command": binPath, "args": []string{"mcp"}})
	if _, stderr, err := runAgentClient(ctx, "code", "--add-mcp", string(payload)); err != nil {
		return agentStep{client.id(), agentFailed, firstAgentError(stderr, err)}
	}
	return agentStep{client.id(), agentConfigured, "MCP server configured"}
}

func (client vscodeAgent) unconfigure(context.Context) agentStep {
	if !exists(client.path()) {
		return agentStep{client.id(), agentSkipped, "open MCP: Open User Configuration to remove non-default profiles"}
	}
	changed, err := removeJSONServer(client.path(), "servers")
	if err != nil {
		return agentStep{client.id(), agentFailed, err.Error()}
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "MCP server removed"}
	}
	return agentStep{client.id(), agentSkipped, "not configured"}
}

func (client vscodeAgent) inspect(_ context.Context, binPath string) agentState {
	state := agentState{client.id(), client.detect(), "unknown", "MCP: Open User Configuration"}
	if exists(client.path()) {
		configured, path, err := inspectJSONServer(client.path(), "servers", binPath)
		if err == nil {
			state.configured, state.path = configured, path
		}
	}
	return state
}

type openClawAgent struct{ home string }

func (client openClawAgent) id() string   { return "openclaw" }
func (client openClawAgent) root() string { return filepath.Join(client.home, ".openclaw", "skills") }
func (client openClawAgent) detect() bool { return exists(filepath.Join(client.home, ".openclaw")) }
func (client openClawAgent) configure(context.Context, string) agentStep {
	changed, err := materializeSkill(client.root())
	if err != nil {
		return agentStep{client.id(), agentFailed, err.Error()}
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "Skill installed; OpenClaw uses the CLI fallback"}
	}
	return agentStep{client.id(), agentSkipped, "Skill already installed"}
}
func (client openClawAgent) unconfigure(context.Context) agentStep {
	changed, err := removeManagedSkill(client.root())
	if err != nil {
		return agentStep{client.id(), agentFailed, err.Error()}
	}
	if changed {
		return agentStep{client.id(), agentConfigured, "Skill removed"}
	}
	return agentStep{client.id(), agentSkipped, "managed Skill not installed"}
}
func (client openClawAgent) inspect(context.Context, string) agentState {
	target := filepath.Join(client.root(), "aegis-ssh")
	configured := "no"
	if exists(filepath.Join(target, ".aegis-managed")) {
		configured = "skill"
	}
	return agentState{client.id(), client.detect(), configured, target}
}

func (application *App) agentCommand(ctx context.Context, args []string) error {
	action, target := "status", "auto"
	if len(args) > 0 {
		action = args[0]
	}
	if len(args) > 1 {
		target = args[1]
	}
	if len(args) > 2 || action != "configure" && action != "unconfigure" && action != "status" {
		return ErrUsage
	}
	clients, binPath, err := application.agentClients()
	if err != nil {
		return err
	}
	selected := clients
	if target != "auto" {
		selected = nil
		for _, client := range clients {
			if client.id() == target {
				selected = []agentClient{client}
				break
			}
		}
		if len(selected) == 0 {
			return ErrUsage
		}
	}
	if action == "status" {
		_, _ = fmt.Fprintln(application.deps.Stdout, application.text("CLIENT\tINSTALLED\tCONFIGURED\tPATH", "客户端\t已安装\t已配置\t路径"))
		for _, client := range selected {
			state := client.inspect(ctx, binPath)
			_, _ = fmt.Fprintf(application.deps.Stdout, "%s\t%s\t%s\t%s\n", state.client, yesNo(state.installed), state.configured, state.path)
		}
		return nil
	}
	failed := false
	for _, client := range selected {
		var step agentStep
		if target == "auto" && !client.detect() {
			step = agentStep{client.id(), agentSkipped, "client not detected"}
		} else if action == "configure" {
			step = client.configure(ctx, binPath)
		} else {
			step = client.unconfigure(ctx)
		}
		_, _ = fmt.Fprintf(application.deps.Stdout, "%s\t%s\t%s\n", step.client, application.agentOutcomeText(step.outcome), application.agentDetail(step.detail))
		failed = failed || step.outcome == agentFailed
	}
	if failed {
		return ErrAgentConfig
	}
	return nil
}

func (application *App) agentClients() ([]agentClient, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", ErrStorage
	}
	binPath, err := os.Executable()
	if err != nil {
		return nil, "", ErrStorage
	}
	binPath, err = filepath.Abs(binPath)
	if err != nil {
		return nil, "", ErrStorage
	}
	return []agentClient{
		cliAgent{name: "codex", command: "codex", configPath: filepath.Join(home, ".codex", "config.toml"), skillRoot: filepath.Join(home, ".codex", "skills"), inspectArgs: []string{"mcp", "get", "aegis-ssh"}, addPrefix: []string{"mcp", "add", "aegis-ssh", "--"}, removeArgs: []string{"mcp", "remove", "aegis-ssh"}},
		cliAgent{name: "claude", command: "claude", configPath: filepath.Join(home, ".claude.json"), skillRoot: filepath.Join(home, ".claude", "skills"), inspectArgs: []string{"mcp", "get", "aegis-ssh"}, addPrefix: []string{"mcp", "add", "-s", "user", "aegis-ssh", "--"}, removeArgs: []string{"mcp", "remove", "-s", "user", "aegis-ssh"}},
		cliAgent{name: "gemini", command: "gemini", configPath: filepath.Join(home, ".gemini", "settings.json"), skillRoot: filepath.Join(home, ".gemini", "skills"), inspectArgs: []string{"mcp", "list"}, addPrefix: []string{"mcp", "add", "-s", "user", "aegis-ssh"}, removeArgs: []string{"mcp", "remove", "-s", "user", "aegis-ssh"}},
		vscodeAgent{home}, cursorAgent{home}, openClawAgent{home},
	}, binPath, nil
}

func runAgentClient(ctx context.Context, name string, args ...string) (string, string, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

func firstAgentError(stderr string, err error) string {
	if line := strings.TrimSpace(strings.SplitN(stderr, "\n", 2)[0]); line != "" {
		return line
	}
	return err.Error()
}

func configuredCommand(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "command:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "command:"))
		}
	}
	return "unknown"
}

func hasMCPArgument(output, binPath string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "args: mcp") || strings.Contains(output, binPath+" mcp")
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func (application *App) agentOutcomeText(outcome agentOutcome) string {
	switch outcome {
	case agentConfigured:
		return application.text("configured", "已配置")
	case agentSkipped:
		return application.text("skipped", "已跳过")
	default:
		return application.text("failed", "失败")
	}
}

func (application *App) agentDetail(detail string) string {
	translations := map[string]string{
		"client not detected":                             "未检测到客户端",
		"already configured":                              "已正确配置",
		"not configured":                                  "尚未配置",
		"Aegis SSH integration installed":                 "Aegis SSH 集成已安装",
		"Aegis SSH integration removed":                   "Aegis SSH 集成已移除",
		"MCP server configured":                           "MCP 服务已配置",
		"MCP server removed":                              "MCP 服务已移除",
		"Skill installed; OpenClaw uses the CLI fallback": "Skill 已安装；OpenClaw 使用 CLI fallback",
		"Skill already installed":                         "Skill 已安装",
		"Skill removed":                                   "Skill 已移除",
		"managed Skill not installed":                     "未安装托管 Skill",
		"open MCP: Open User Configuration to remove non-default profiles": "请使用 MCP: Open User Configuration 移除非默认 profile",
	}
	if translated, ok := translations[detail]; ok {
		return application.text(detail, translated)
	}
	return detail
}

func upsertJSONServer(path, mapKey, binPath string) (bool, error) {
	root, servers, err := loadJSONServers(path, mapKey)
	if err != nil {
		return false, err
	}
	entry, _ := json.Marshal(map[string]any{"command": binPath, "args": []string{"mcp"}})
	if current, ok := servers["aegis-ssh"]; ok {
		command, args, parseErr := parseJSONServer(current)
		if parseErr == nil && command == binPath && len(args) == 1 && args[0] == "mcp" {
			return false, nil
		}
	}
	servers["aegis-ssh"] = entry
	return true, saveJSONServers(path, mapKey, root, servers)
}

func removeJSONServer(path, mapKey string) (bool, error) {
	if !exists(path) {
		return false, nil
	}
	root, servers, err := loadJSONServers(path, mapKey)
	if err != nil {
		return false, err
	}
	if _, ok := servers["aegis-ssh"]; !ok {
		return false, nil
	}
	delete(servers, "aegis-ssh")
	return true, saveJSONServers(path, mapKey, root, servers)
}

func inspectJSONServer(path, mapKey, binPath string) (string, string, error) {
	if !exists(path) {
		return "no", "-", nil
	}
	_, servers, err := loadJSONServers(path, mapKey)
	if err != nil {
		return "", "", err
	}
	raw, ok := servers["aegis-ssh"]
	if !ok {
		return "no", "-", nil
	}
	command, args, err := parseJSONServer(raw)
	if err != nil {
		return "", "", err
	}
	if command == binPath && len(args) == 1 && args[0] == "mcp" {
		return "yes", command, nil
	}
	return "stale", command, nil
}

func parseJSONServer(raw []byte) (string, []string, error) {
	var entry struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return "", nil, err
	}
	return entry.Command, entry.Args, nil
}

func loadJSONServers(path, mapKey string) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	root := map[string]json.RawMessage{}
	if exists(path) {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, nil, errors.New("refusing unsafe agent config path")
		}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &root) != nil || root == nil {
			return nil, nil, errors.New("unable to parse agent config")
		}
	}
	servers := map[string]json.RawMessage{}
	if raw, ok := root[mapKey]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return nil, nil, errors.New("agent config server map is not an object")
		}
		if servers == nil {
			return nil, nil, errors.New("agent config server map is not an object")
		}
	}
	return root, servers, nil
}

func saveJSONServers(path, mapKey string, root, servers map[string]json.RawMessage) error {
	raw, err := json.Marshal(servers)
	if err != nil {
		return err
	}
	root[mapKey] = raw
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomicWithBackup(path, data, 0o600)
}

func writeFileAtomicWithBackup(path string, data []byte, perm fs.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refusing unsafe agent config path")
		}
		original, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := writeAtomicFile(path+".bak", original, info.Mode().Perm()); err != nil {
			return err
		}
		perm = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomicFile(path, data, perm)
}

func writeAtomicFile(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing unsafe agent config path")
	}
	temp, err := os.CreateTemp(dir, ".aegis-agent-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(perm); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func materializeSkill(root string) (bool, error) {
	target := filepath.Join(root, "aegis-ssh")
	marker := filepath.Join(target, ".aegis-managed")
	managed, err := isManagedSkill(target)
	if err != nil {
		return false, err
	}
	if exists(target) && !managed {
		return false, errors.New("refusing to overwrite unmanaged aegis-ssh Skill")
	}
	if managed {
		data, err := os.ReadFile(marker)
		if err == nil && strings.TrimSpace(string(data)) == Version {
			return false, nil
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return false, err
	}
	temp, err := os.MkdirTemp(root, ".aegis-skill-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(temp)
	err = fs.WalkDir(embeddedskills.FS, "aegis-ssh", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, _ := filepath.Rel("aegis-ssh", path)
		destination := filepath.Join(temp, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		data, err := fs.ReadFile(embeddedskills.FS, path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0o644)
	})
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(temp, ".aegis-managed"), []byte(Version+"\n"), 0o644); err != nil {
		return false, err
	}
	old := target + ".old"
	if exists(old) {
		return false, errors.New("refusing to overwrite existing Skill backup")
	}
	if exists(target) {
		if err := os.Rename(target, old); err != nil {
			return false, err
		}
	}
	if err := os.Rename(temp, target); err != nil {
		if exists(old) {
			_ = os.Rename(old, target)
		}
		return false, err
	}
	_ = os.RemoveAll(old)
	return true, nil
}

func removeManagedSkill(root string) (bool, error) {
	target := filepath.Join(root, "aegis-ssh")
	if !exists(target) {
		return false, nil
	}
	managed, err := isManagedSkill(target)
	if err != nil {
		return false, err
	}
	if !managed {
		return false, nil
	}
	return true, os.RemoveAll(target)
}

func isManagedSkill(target string) (bool, error) {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("refusing unsafe Skill path")
	}
	marker, err := os.Lstat(filepath.Join(target, ".aegis-managed"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || marker.Mode()&os.ModeSymlink != 0 || !marker.Mode().IsRegular() {
		return false, errors.New("refusing unsafe Skill marker")
	}
	return true, nil
}
