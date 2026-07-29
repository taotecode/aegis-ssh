package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/chenjw/aegis-ssh/internal/broker"
	"github.com/chenjw/aegis-ssh/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const implementationVersion = "0.1.0"

var ErrInvalidServer = errors.New("invalid MCP server configuration")

type BrokerClient interface {
	Status(context.Context) (model.BrokerStatus, error)
	ListServers(context.Context) ([]model.ServerSummary, error)
	Execute(context.Context, model.ExecuteRequest) (model.ExecuteResult, error)
	ExecuteApproved(context.Context, model.ApprovedRequest) (model.ExecuteResult, error)
}

type Server struct {
	inner *mcp.Server
}

func New(client BrokerClient) *Server {
	inner := mcp.NewServer(&mcp.Implementation{Name: "aegis-ssh", Version: implementationVersion}, nil)
	registerStatusTool(inner, client)
	registerListTool(inner, client)
	registerExecuteTool(inner, client)
	registerApprovedTool(inner, client)
	return &Server{inner: inner}
}

func (server *Server) Run(ctx context.Context, transport mcp.Transport) error {
	if server == nil || server.inner == nil || ctx == nil || transport == nil {
		return ErrInvalidServer
	}
	return server.inner.Run(ctx, transport)
}

func (server *Server) RunStdio(ctx context.Context) error {
	return server.Run(ctx, &mcp.StdioTransport{})
}

type emptyInput struct{}

type executeInput struct {
	ServerAlias    string `json:"server_alias" jsonschema:"public server alias; never a host or address"`
	Command        string `json:"command" jsonschema:"exact non-interactive shell command to execute remotely"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"optional bounded execution timeout in seconds"`
	MaxOutputBytes int64  `json:"max_output_bytes,omitempty" jsonschema:"optional bounded stdout and stderr limit in bytes"`
}

type approvedInput struct {
	ApprovalID   string `json:"approval_id" jsonschema:"single-use approval identifier returned by ssh_execute"`
	ApprovalCode string `json:"approval_code" jsonschema:"four-character code explicitly confirmed by the user"`
}

type statusOutput struct {
	DaemonReachable bool   `json:"daemon_reachable"`
	VaultLocked     bool   `json:"vault_locked"`
	Version         string `json:"version"`
	PolicyVersion   string `json:"policy_version"`
	AuditFailClosed bool   `json:"audit_fail_closed"`
}

type listOutput struct {
	Servers []serverOutput `json:"servers"`
}

type serverOutput struct {
	Alias       string `json:"alias"`
	Description string `json:"description,omitempty"`
	Available   bool   `json:"available"`
}

type executeOutput struct {
	Status     model.Status    `json:"status"`
	Stdout     string          `json:"stdout,omitempty"`
	Stderr     string          `json:"stderr,omitempty"`
	ExitCode   int             `json:"exit_code"`
	DurationMS int64           `json:"duration_ms,omitempty"`
	Truncated  bool            `json:"truncated"`
	Error      *errorOutput    `json:"error,omitempty"`
	Warnings   []*errorOutput  `json:"warnings,omitempty"`
	Approval   *approvalOutput `json:"approval,omitempty"`
	Redactions redactionOutput `json:"redactions"`
}

type errorOutput struct {
	Code    model.ErrorCode `json:"code"`
	Message string          `json:"message"`
}

type approvalOutput struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type redactionOutput struct {
	Applied bool           `json:"applied"`
	Counts  map[string]int `json:"counts,omitempty"`
}

func registerStatusTool(server *mcp.Server, client BrokerClient) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_ssh_broker_status",
		Description: "Return daemon, lock, version, policy, and audit status. " +
			"The tool never exposes SSH credentials or connection details.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, statusOutput, error) {
		if client == nil {
			return nil, statusOutput{}, safeBrokerError(broker.ErrUnavailable)
		}
		status, err := client.Status(ctx)
		if err != nil {
			return nil, statusOutput{}, safeBrokerError(err)
		}
		output := statusOutput{
			DaemonReachable: status.DaemonReachable,
			VaultLocked:     status.VaultLocked,
			Version:         status.Version,
			PolicyVersion:   status.PolicyVersion,
			AuditFailClosed: status.AuditFailClosed,
		}
		message := "SSH broker is ready."
		if status.VaultLocked {
			message = "SSH broker is locked. Start and unlock the daemon before running SSH tools."
		} else if !status.DaemonReachable {
			message = "SSH broker is not reachable. Start the daemon before running SSH tools."
		}
		return textResult(message, false), output, nil
	})
}

func registerListTool(server *mcp.Server, client BrokerClient) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "list_ssh_servers",
		Description: "List public server aliases, descriptions, and availability. " +
			"The tool never exposes SSH credentials or connection details.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, listOutput, error) {
		if client == nil {
			return nil, listOutput{}, safeBrokerError(broker.ErrUnavailable)
		}
		servers, err := client.ListServers(ctx)
		if err != nil {
			return nil, listOutput{}, safeBrokerError(err)
		}
		output := listOutput{Servers: make([]serverOutput, len(servers))}
		for index, server := range servers {
			output.Servers[index] = serverOutput{Alias: server.Alias, Description: server.Description, Available: server.Available}
		}
		return textResult(fmt.Sprintf("Found %d configured SSH server aliases.", len(output.Servers)), false), output, nil
	})
}

func registerExecuteTool(server *mcp.Server, client BrokerClient) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "ssh_execute",
		Description: "Execute an exact non-interactive shell command through a public server alias. " +
			"Returns filtered output or an approval request and never exposes SSH credentials or connection details.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input executeInput) (*mcp.CallToolResult, executeOutput, error) {
		if client == nil {
			return nil, executeOutput{}, safeBrokerError(broker.ErrUnavailable)
		}
		result, err := client.Execute(ctx, model.ExecuteRequest{
			ServerAlias: input.ServerAlias, Command: input.Command,
			TimeoutSeconds: input.TimeoutSeconds, MaxOutputBytes: input.MaxOutputBytes,
		})
		if err != nil {
			return nil, executeOutput{}, safeBrokerError(err)
		}
		return executeToolResult(result)
	})
}

func registerApprovedTool(server *mcp.Server, client BrokerClient) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "ssh_execute_approved",
		Description: "Execute the stored command for a user-confirmed, single-use approval. " +
			"Accepts no replacement command and never exposes SSH credentials or connection details.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input approvedInput) (*mcp.CallToolResult, executeOutput, error) {
		if client == nil {
			return nil, executeOutput{}, safeBrokerError(broker.ErrUnavailable)
		}
		result, err := client.ExecuteApproved(ctx, model.ApprovedRequest{
			ApprovalID: input.ApprovalID, ApprovalCode: input.ApprovalCode,
		})
		if err != nil {
			return nil, executeOutput{}, safeBrokerError(err)
		}
		return executeToolResult(result)
	})
}

func executeToolResult(result model.ExecuteResult) (*mcp.CallToolResult, executeOutput, error) {
	output := publicExecuteOutput(result)
	message := "SSH command completed. See structured output for stdout and stderr."
	isError := false
	switch result.Status {
	case model.StatusRequiresApproval:
		if result.Approval != nil && result.Approval.Message != "" {
			message = result.Approval.Message
		} else {
			message = "SSH command requires user approval, but approval details are unavailable."
			isError = true
		}
	case model.StatusDenied:
		message = "SSH command was denied by policy."
		isError = true
	case model.StatusFailed:
		message = "SSH command failed."
		if result.Error != nil {
			message = "SSH command failed: " + result.Error.Error() + "."
		}
		isError = true
	case model.StatusCompleted:
		if len(result.Warnings) != 0 {
			message = "SSH command completed with warnings. See structured output for details."
		}
	default:
		message = "SSH broker returned an invalid execution status."
		isError = true
	}
	return textResult(message, isError), output, nil
}

func publicExecuteOutput(result model.ExecuteResult) executeOutput {
	output := executeOutput{
		Status: result.Status, Stdout: result.Stdout, Stderr: result.Stderr,
		ExitCode: result.ExitCode, DurationMS: result.DurationMS, Truncated: result.Truncated,
		Error:      publicError(result.Error),
		Redactions: redactionOutput{Applied: result.Redactions.Applied, Counts: cloneCounts(result.Redactions.Counts)},
	}
	if len(result.Warnings) != 0 {
		output.Warnings = make([]*errorOutput, len(result.Warnings))
		for index, warning := range result.Warnings {
			output.Warnings[index] = publicError(warning)
		}
	}
	if result.Approval != nil {
		output.Approval = &approvalOutput{
			ID: result.Approval.ID, Code: result.Approval.Code,
			Message: result.Approval.Message, ExpiresAt: result.Approval.ExpiresAt,
		}
	}
	return output
}

func publicError(err *model.CodedError) *errorOutput {
	if err == nil {
		return nil
	}
	return &errorOutput{Code: err.Code(), Message: err.Error()}
}

func cloneCounts(counts map[string]int) map[string]int {
	if len(counts) == 0 {
		return nil
	}
	result := make(map[string]int, len(counts))
	for category, count := range counts {
		result[category] = count
	}
	return result
}

func textResult(message string, isError bool) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: message}},
		IsError: isError,
	}
}

func safeBrokerError(err error) error {
	switch {
	case errors.Is(err, model.ErrLockedVault):
		return errors.New("SSH broker is locked; start and unlock the daemon before retrying")
	case errors.Is(err, broker.ErrUnavailable):
		return errors.New("SSH broker is unavailable; start and unlock the daemon before retrying")
	case errors.Is(err, context.Canceled):
		return errors.New("SSH broker request was canceled")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, model.ErrTimeout):
		return errors.New("SSH broker request timed out")
	case errors.Is(err, model.ErrAuthentication):
		return errors.New("SSH authentication failed")
	case errors.Is(err, model.ErrConnection):
		return errors.New("SSH connection failed")
	case errors.Is(err, model.ErrHostKey):
		return errors.New("SSH host-key verification failed")
	case errors.Is(err, model.ErrApproval):
		return errors.New("SSH approval failed")
	case errors.Is(err, model.ErrAudit):
		return errors.New("SSH audit operation failed")
	case errors.Is(err, model.ErrValidation):
		return errors.New("SSH broker rejected the request")
	default:
		return errors.New("SSH broker request failed")
	}
}
