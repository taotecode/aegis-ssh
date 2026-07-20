package policy

import (
	"errors"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	maxCommandBytes = 128 << 10
	maxShellDepth   = 4
)

type Category string

const (
	SSHSecret          Category = "ssh_secret"
	CloudCredential    Category = "cloud_credential"
	ProcessEnvironment Category = "process_environment"
	DatabaseCredential Category = "database_credential"
	KubernetesSecret   Category = "kubernetes_secret"
	PrivateKey         Category = "private_key"
	NetworkIdentity    Category = "network_identity"
)

type Finding struct {
	Category Category
	Rule     string
	Evidence string
}

type Analysis struct {
	Categories []Category
	Findings   []Finding
}

type Analyzer struct{}

type staticArg struct {
	Value string
	Known bool
}

var ErrInvalidShell = errors.New("invalid shell command")

func NewAnalyzer() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Analyze(command string) (Analysis, error) {
	if strings.TrimSpace(command) == "" || len(command) > maxCommandBytes {
		return Analysis{}, ErrInvalidShell
	}
	findings, err := a.analyze(command, 0)
	if err != nil {
		return Analysis{}, ErrInvalidShell
	}
	return buildAnalysis(findings), nil
}

func (a *Analyzer) analyze(command string, depth int) ([]Finding, error) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, err
	}
	if len(file.Stmts) == 0 {
		return nil, ErrInvalidShell
	}

	var findings []Finding
	excludedWords := make(map[*syntax.Word]struct{})
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			args := makeStaticArgs(node.Args)
			if len(args) == 0 {
				return true
			}
			findings = append(findings, classifyCall(args)...)
			if invocation, ok := parseShellInvocation(node.Args); ok {
				for _, word := range node.Args[invocation.positionalStart:] {
					excludedWords[word] = struct{}{}
				}
				if depth < maxShellDepth && invocation.commandStringIndex >= 0 && invocation.commandStringKnown {
					nested, nestedErr := a.analyze(invocation.commandString, depth+1)
					if nestedErr == nil {
						findings = append(findings, nested...)
					}
				}
			}
		case *syntax.Word:
			if _, excluded := excludedWords[node]; excluded {
				break
			}
			if value, ok := staticWord(node); ok {
				findings = append(findings, classifyPath(value)...)
			}
		case *syntax.DeclClause:
			if node.Variant.Value == "export" && (len(node.Args) == 0 || declHasOption(node, "-p")) {
				findings = append(findings, labeledFinding(ProcessEnvironment, labelEnvironmentCommand))
			}
		case *syntax.ParamExp:
			if name, ok := simpleParameterName(node); ok && isCloudEnvironment(name) {
				findings = append(findings, labeledFinding(CloudCredential, labelCloudEnvironment))
			}
		}
		return true
	})
	return findings, nil
}

func makeStaticArgs(words []*syntax.Word) []staticArg {
	result := make([]staticArg, len(words))
	for i, word := range words {
		result[i].Value, result[i].Known = staticWord(word)
	}
	return result
}

func staticWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	for _, part := range word.Parts {
		if !writeStaticPart(&value, part) {
			return "", false
		}
	}
	return value.String(), true
}

func writeStaticPart(value *strings.Builder, part syntax.WordPart) bool {
	switch part := part.(type) {
	case *syntax.Lit:
		value.WriteString(part.Value)
		return true
	case *syntax.SglQuoted:
		value.WriteString(part.Value)
		return true
	case *syntax.DblQuoted:
		for _, nested := range part.Parts {
			if !writeStaticPart(value, nested) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		if name, ok := simpleParameterName(part); ok && name == "HOME" {
			value.WriteByte('~')
			return true
		}
	}
	return false
}

func simpleParameterName(param *syntax.ParamExp) (string, bool) {
	if param.Param == nil || param.Flags != nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.NestedParam != nil || param.Index != nil || len(param.Modifiers) != 0 || param.Slice != nil ||
		param.Repl != nil || param.Names != 0 || param.Exp != nil {
		return "", false
	}
	return param.Param.Value, true
}

func declHasOption(decl *syntax.DeclClause, option string) bool {
	for _, arg := range decl.Args {
		if arg.Value == nil {
			continue
		}
		if value, ok := staticWord(arg.Value); ok && value == option {
			return true
		}
	}
	return false
}

func buildAnalysis(findings []Finding) Analysis {
	seen := make(map[Finding]struct{}, len(findings))
	unique := findings[:0]
	for _, finding := range findings {
		if _, ok := seen[finding]; ok {
			continue
		}
		seen[finding] = struct{}{}
		unique = append(unique, finding)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Category != unique[j].Category {
			return unique[i].Category < unique[j].Category
		}
		if unique[i].Rule != unique[j].Rule {
			return unique[i].Rule < unique[j].Rule
		}
		return unique[i].Evidence < unique[j].Evidence
	})

	categories := make([]Category, 0, len(unique))
	for _, finding := range unique {
		if len(categories) == 0 || categories[len(categories)-1] != finding.Category {
			categories = append(categories, finding.Category)
		}
	}
	if len(categories) == 0 {
		categories = nil
		unique = nil
	}
	return Analysis{Categories: categories, Findings: unique}
}
