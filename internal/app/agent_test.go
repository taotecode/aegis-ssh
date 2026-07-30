package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taotecode/aegis-ssh/internal/app"
)

func TestAgentCLIIntegrationsAreIdempotentAndRemovable(t *testing.T) {
	tests := []struct {
		client, inspect, add, remove, skill string
	}{
		{"codex", "mcp get aegis-ssh", "mcp add aegis-ssh -- ", "mcp remove aegis-ssh", ".codex/skills"},
		{"claude", "mcp get aegis-ssh", "mcp add -s user aegis-ssh -- ", "mcp remove -s user aegis-ssh", ".claude/skills"},
		{"gemini", "mcp list", "mcp add -s user aegis-ssh ", "mcp remove -s user aegis-ssh", ".gemini/skills"},
	}
	for _, test := range tests {
		t.Run(test.client, func(t *testing.T) {
			home, binDir := t.TempDir(), t.TempDir()
			logPath, statePath := filepath.Join(t.TempDir(), "calls"), filepath.Join(t.TempDir(), "state")
			writeAgentShim(t, filepath.Join(binDir, test.client))
			t.Setenv("HOME", home)
			t.Setenv("PATH", binDir)
			t.Setenv("LC_ALL", "C")
			t.Setenv("LC_MESSAGES", "C")
			t.Setenv("LANG", "C")
			t.Setenv("AEGIS_TEST_LOG", logPath)
			t.Setenv("AEGIS_TEST_STATE", statePath)

			var output bytes.Buffer
			application := app.New(app.Dependencies{Stdout: &output, Stderr: &output})
			if err := application.Run(context.Background(), []string{"agent", "configure", test.client}); err != nil {
				t.Fatal(err)
			}
			executable, _ := os.Executable()
			log := readTestFile(t, logPath)
			if !strings.Contains(log, test.inspect) || !strings.Contains(log, test.add+executable+" mcp") {
				t.Fatalf("unexpected calls:\n%s", log)
			}
			marker := filepath.Join(home, test.skill, "aegis-ssh", ".aegis-managed")
			if got := strings.TrimSpace(readTestFile(t, marker)); got != app.Version {
				t.Fatalf("managed marker = %q", got)
			}

			before := strings.Count(log, "mcp add")
			output.Reset()
			if err := application.Run(context.Background(), []string{"agent", "configure", test.client}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "skipped") {
				t.Fatalf("second configure output = %q", output.String())
			}
			if after := strings.Count(readTestFile(t, logPath), "mcp add"); after != before {
				t.Fatalf("idempotent configure added again: before=%d after=%d", before, after)
			}

			if err := application.Run(context.Background(), []string{"agent", "unconfigure", test.client}); err != nil {
				t.Fatal(err)
			}
			if existsForTest(statePath) {
				t.Fatal("MCP state remains after unconfigure")
			}
			if existsForTest(marker) {
				t.Fatal("managed Skill remains after unconfigure")
			}
			if !strings.Contains(readTestFile(t, logPath), test.remove) {
				t.Fatalf("remove call missing:\n%s", readTestFile(t, logPath))
			}
		})
	}
}

func TestCursorConfigPreservesOtherEntriesAndBacksUp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_MESSAGES", "C")
	t.Setenv("LANG", "C")
	path := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\n  \"theme\": \"dark\",\n  \"mcpServers\": {\"other\": {\"command\": \"other\"}}\n}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	application := app.New(app.Dependencies{Stdout: &output, Stderr: &output})
	if err := application.Run(context.Background(), []string{"agent", "configure", "cursor"}); err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(readTestFile(t, path)), &root); err != nil {
		t.Fatal(err)
	}
	servers := root["mcpServers"].(map[string]any)
	if root["theme"] != "dark" || servers["other"] == nil || servers["aegis-ssh"] == nil {
		t.Fatalf("merged config = %#v", root)
	}
	if got := readTestFile(t, path+".bak"); got != string(original) {
		t.Fatalf("backup = %q, want %q", got, original)
	}
	servers["aegis-ssh"] = map[string]any{"args": []any{"mcp"}, "command": servers["aegis-ssh"].(map[string]any)["command"], "env": map[string]any{"KEEP": "yes"}}
	reordered, _ := json.Marshal(root)
	if err := os.WriteFile(path, reordered, 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := application.Run(context.Background(), []string{"agent", "configure", "cursor"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "skipped") {
		t.Fatalf("semantic duplicate was rewritten: %q", output.String())
	}
	if !strings.Contains(readTestFile(t, path), "\"KEEP\":\"yes\"") {
		t.Fatal("existing MCP fields were not preserved")
	}
	if err := application.Run(context.Background(), []string{"agent", "unconfigure", "cursor"}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(readTestFile(t, path)), &root); err != nil {
		t.Fatal(err)
	}
	servers = root["mcpServers"].(map[string]any)
	if servers["other"] == nil || servers["aegis-ssh"] != nil {
		t.Fatalf("config after removal = %#v", root)
	}
}

func TestAgentConfigRefusesInvalidFilesAndUnmanagedSkills(t *testing.T) {
	for name, content := range map[string]string{"invalid JSON": "{broken", "null root": "null", "null server map": "{\"mcpServers\":null}"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("PATH", t.TempDir())
			path := filepath.Join(home, ".cursor", "mcp.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
			err := application.Run(context.Background(), []string{"agent", "configure", "cursor"})
			if !errors.Is(err, app.ErrAgentConfig) || readTestFile(t, path) != content {
				t.Fatalf("configure error=%v content=%q", err, readTestFile(t, path))
			}
		})
	}

	t.Run("symlink JSON", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions vary on Windows")
		}
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PATH", t.TempDir())
		dir := filepath.Join(home, ".cursor")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "mcp.json")); err != nil {
			t.Fatal(err)
		}
		application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if err := application.Run(context.Background(), []string{"agent", "configure", "cursor"}); !errors.Is(err, app.ErrAgentConfig) {
			t.Fatalf("configure error = %v", err)
		}
		if readTestFile(t, target) != "{}" {
			t.Fatal("symlink target was modified")
		}
	})

	t.Run("unmanaged Skill", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PATH", t.TempDir())
		skill := filepath.Join(home, ".openclaw", "skills", "aegis-ssh")
		if err := os.MkdirAll(skill, 0o755); err != nil {
			t.Fatal(err)
		}
		userFile := filepath.Join(skill, "SKILL.md")
		if err := os.WriteFile(userFile, []byte("user content"), 0o644); err != nil {
			t.Fatal(err)
		}
		application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if err := application.Run(context.Background(), []string{"agent", "configure", "openclaw"}); !errors.Is(err, app.ErrAgentConfig) {
			t.Fatalf("configure error = %v", err)
		}
		if err := application.Run(context.Background(), []string{"agent", "unconfigure", "openclaw"}); err != nil {
			t.Fatal(err)
		}
		if readTestFile(t, userFile) != "user content" {
			t.Fatal("unmanaged Skill was changed")
		}
	})

	t.Run("symlink Skill marker", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions vary on Windows")
		}
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PATH", t.TempDir())
		skill := filepath.Join(home, ".openclaw", "skills", "aegis-ssh")
		if err := os.MkdirAll(skill, 0o755); err != nil {
			t.Fatal(err)
		}
		markerTarget := filepath.Join(t.TempDir(), "marker")
		if err := os.WriteFile(markerTarget, []byte(app.Version), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(markerTarget, filepath.Join(skill, ".aegis-managed")); err != nil {
			t.Fatal(err)
		}
		application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if err := application.Run(context.Background(), []string{"agent", "unconfigure", "openclaw"}); !errors.Is(err, app.ErrAgentConfig) {
			t.Fatalf("unconfigure error = %v", err)
		}
		if !existsForTest(skill) {
			t.Fatal("Skill with unsafe marker was removed")
		}
	})

	t.Run("existing Skill backup is preserved", func(t *testing.T) {
		home := t.TempDir()
		binDir := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PATH", binDir)
		writeAgentShim(t, filepath.Join(binDir, "codex"))
		root := filepath.Join(home, ".codex", "skills")
		backup := filepath.Join(root, "aegis-ssh.old")
		if err := os.MkdirAll(backup, 0o755); err != nil {
			t.Fatal(err)
		}
		keep := filepath.Join(backup, "keep")
		if err := os.WriteFile(keep, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if err := application.Run(context.Background(), []string{"agent", "configure", "codex"}); !errors.Is(err, app.ErrAgentConfig) {
			t.Fatalf("configure error = %v", err)
		}
		if readTestFile(t, keep) != "keep" {
			t.Fatal("existing Skill backup was changed")
		}
	})

	t.Run("missing CLI leaves MCP config", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PATH", t.TempDir())
		configPath := filepath.Join(home, ".codex", "config.toml")
		if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, []byte("[mcp_servers.aegis-ssh]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if err := application.Run(context.Background(), []string{"agent", "unconfigure", "codex"}); !errors.Is(err, app.ErrAgentConfig) {
			t.Fatalf("unconfigure error = %v", err)
		}
		if !existsForTest(configPath) {
			t.Fatal("MCP config was removed without its native CLI")
		}
	})
}

func TestVSCodeUsesOfficialMinimalMCPPayload(t *testing.T) {
	home, binDir := t.TempDir(), t.TempDir()
	logPath := filepath.Join(t.TempDir(), "calls")
	writeAgentShim(t, filepath.Join(binDir, "code"))
	t.Setenv("HOME", home)
	t.Setenv("PATH", binDir)
	t.Setenv("AEGIS_TEST_LOG", logPath)
	t.Setenv("AEGIS_TEST_STATE", filepath.Join(t.TempDir(), "state"))
	application := app.New(app.Dependencies{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err := application.Run(context.Background(), []string{"agent", "configure", "vscode"}); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(readTestFile(t, logPath))
	const prefix = "--add-mcp "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("code call = %q", line)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["name"] != "aegis-ssh" || payload["type"] != nil {
		t.Fatalf("payload = %#v", payload)
	}
}

func writeAgentShim(t *testing.T, path string) {
	t.Helper()
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$AEGIS_TEST_LOG"
case "$*" in
  "mcp get aegis-ssh")
    [ -f "$AEGIS_TEST_STATE" ] || exit 1
    /bin/cat "$AEGIS_TEST_STATE"
    ;;
  "mcp list")
    [ ! -f "$AEGIS_TEST_STATE" ] || /bin/cat "$AEGIS_TEST_STATE"
    ;;
  *"mcp add"*|"--add-mcp "*)
    printf 'aegis-ssh %s\n' "$*" > "$AEGIS_TEST_STATE"
    ;;
  *"mcp remove"*)
    /bin/rm -f "$AEGIS_TEST_STATE"
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func existsForTest(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
