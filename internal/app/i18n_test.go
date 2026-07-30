package app

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpAutomaticallyUsesChineseLocale(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	var output bytes.Buffer
	application := New(Dependencies{Root: filepath.Join(t.TempDir(), "aegis"), Stdout: &output, Stderr: &output})
	if err := application.Run(context.Background(), []string{"--help"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "用法") || !strings.Contains(output.String(), "本机处理风险审批") {
		t.Fatalf("help=%q", output.String())
	}
}

func TestExplicitEnglishOverridesChineseLocale(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	if got := resolveLanguage("en"); got != languageEnglish {
		t.Fatalf("language=%q", got)
	}
}
