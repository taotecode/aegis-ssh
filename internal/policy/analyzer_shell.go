package policy

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type shellInvocation struct {
	commandStringIndex int
	commandString      string
	commandStringKnown bool
	positionalStart    int
}

type shellOptionSpec struct {
	shortOptions         string
	clusterValueOptions  string
	valueOptions         map[string]struct{}
	attachedNamedOptions map[string]struct{}
	flagOptions          map[string]struct{}
	prefixOptions        []string
	allowPlusShort       bool
}

func parseShellInvocation(words []*syntax.Word) (shellInvocation, bool) {
	if len(words) == 0 {
		return shellInvocation{}, false
	}
	command, ok := staticWord(words[0])
	if !ok {
		return shellInvocation{}, false
	}

	var spec shellOptionSpec
	switch filepath.Base(command) {
	case "bash":
		spec = bashOptionSpec()
	case "sh", "dash":
		spec = posixShellOptionSpec()
	case "zsh":
		spec = zshOptionSpec()
	default:
		return shellInvocation{}, false
	}
	return parseShellOptions(words, spec), true
}

func parseShellOptions(words []*syntax.Word, spec shellOptionSpec) shellInvocation {
	invocation := shellInvocation{commandStringIndex: -1, positionalStart: len(words)}
	for i := 1; i < len(words); i++ {
		option, known := staticWord(words[i])
		if !known {
			invocation.positionalStart = i
			return invocation
		}
		if option == "--" {
			invocation.positionalStart = min(i+2, len(words))
			return invocation
		}
		if _, ok := spec.valueOptions[option]; ok {
			if i+1 >= len(words) {
				return invocation
			}
			i++
			continue
		}
		if matched, valid := parseAttachedNamedOption(option, spec.attachedNamedOptions); matched {
			if !valid {
				invocation.positionalStart = i
				return invocation
			}
			continue
		}
		if _, ok := spec.flagOptions[option]; ok {
			continue
		}
		if hasOptionPrefix(option, spec.prefixOptions) {
			continue
		}
		if len(option) < 2 || option[0] != '-' && (!spec.allowPlusShort || option[0] != '+') {
			invocation.positionalStart = i + 1
			return invocation
		}

		hasCommandString, consumesValue, valid := parseShortOptionCluster(option[1:], spec.shortOptions, spec.clusterValueOptions)
		if !valid {
			invocation.positionalStart = i
			return invocation
		}
		if consumesValue {
			if i+1 >= len(words) {
				return invocation
			}
			i++
		}
		if hasCommandString {
			if i+1 >= len(words) {
				return invocation
			}
			invocation.commandStringIndex = i + 1
			invocation.positionalStart = i + 1
			invocation.commandString, invocation.commandStringKnown = staticWord(words[i+1])
			return invocation
		}
	}
	return invocation
}

func parseShortOptionCluster(cluster, supported, valueOptions string) (hasCommandString, consumesValue, valid bool) {
	for _, option := range cluster {
		if strings.ContainsRune(valueOptions, option) {
			consumesValue = true
			continue
		}
		if option == 'c' {
			hasCommandString = true
			continue
		}
		if !strings.ContainsRune(supported, option) {
			return false, false, false
		}
	}
	return hasCommandString, consumesValue, cluster != ""
}

func parseAttachedNamedOption(option string, supported map[string]struct{}) (matched, valid bool) {
	if len(supported) == 0 || len(option) <= 2 || option[:2] != "-o" && option[:2] != "+o" {
		return false, false
	}
	_, valid = supported[option[2:]]
	return true, valid
}

func hasOptionPrefix(option string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(option, prefix) {
			return true
		}
	}
	return false
}

func bashOptionSpec() shellOptionSpec {
	return shellOptionSpec{
		shortOptions:        "abefhkmnptuvxBCEHPTDilsr",
		clusterValueOptions: "oO",
		valueOptions:        stringSet("-O", "-o", "+O", "+o", "--rcfile", "--init-file"),
		flagOptions:         stringSet("--noprofile", "--norc", "--posix", "--restricted", "--verbose", "--debugger", "--noediting", "--login"),
		prefixOptions:       []string{"--rcfile=", "--init-file="},
		allowPlusShort:      true,
	}
}

func posixShellOptionSpec() shellOptionSpec {
	return shellOptionSpec{
		shortOptions:        "abefkmnptuvxilsr",
		clusterValueOptions: "o",
		valueOptions:        stringSet("-o", "+o"),
		flagOptions:         map[string]struct{}{},
		allowPlusShort:      true,
	}
}

func zshOptionSpec() shellOptionSpec {
	return shellOptionSpec{
		shortOptions:         "abefhkmnptuvxDilsrdy",
		clusterValueOptions:  "o",
		valueOptions:         stringSet("-o", "+o"),
		attachedNamedOptions: stringSet("norcs", "rcs", "noglobalrcs", "globalrcs", "norcexpandparam", "rcexpandparam"),
		flagOptions:          stringSet("--no-rcs", "--no-globalrcs", "--rcs", "--globalrcs", "--no-rcexpandparam", "--rcexpandparam"),
		allowPlusShort:       true,
	}
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
