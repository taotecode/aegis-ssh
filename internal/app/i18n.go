package app

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/taotecode/aegis-ssh/internal/config"
	"github.com/taotecode/aegis-ssh/internal/paths"
)

type language string

const (
	languageEnglish language = "en"
	languageChinese language = "zh-CN"
)

func resolveLanguage(configured string) language {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "zh", "zh-cn", "zh_cn":
		return languageChinese
	case "en", "en-us", "en_us":
		return languageEnglish
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if strings.HasPrefix(strings.ToLower(os.Getenv(key)), "zh") {
			return languageChinese
		}
	}
	return languageEnglish
}

func localize(lang language, english, chinese string) string {
	if lang == languageChinese {
		return chinese
	}
	return english
}

func (application *App) language() language {
	lang := resolveLanguage("auto")
	root := application.deps.Root
	if root == "" {
		var err error
		root, err = paths.DefaultRoot()
		if err != nil {
			return lang
		}
	}
	cfg, err := config.Load(filepath.Join(root, "config.yaml"))
	if err == nil {
		return resolveLanguage(cfg.Language)
	}
	return lang
}
func (application *App) text(english, chinese string) string {
	return localize(application.language(), english, chinese)
}
