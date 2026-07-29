package mcpserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/taotecode/aegis-ssh/internal/broker"
	"github.com/taotecode/aegis-ssh/internal/mcpserver"
	"github.com/taotecode/aegis-ssh/internal/model"
)

type fakeBrokerClient struct {
	mu             sync.Mutex
	status         model.BrokerStatus
	servers        []model.ServerSummary
	executeResult  model.ExecuteResult
	approvedResult model.ExecuteResult
	err            error
	executes       []model.ExecuteRequest
	approved       []model.ApprovedRequest
	statusCalls    int
	listCalls      int
}

func (client *fakeBrokerClient) Status(context.Context) (model.BrokerStatus, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.statusCalls++
	return client.status, client.err
}

func (client *fakeBrokerClient) ListServers(context.Context) ([]model.ServerSummary, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.listCalls++
	return append([]model.ServerSummary(nil), client.servers...), client.err
}

func (client *fakeBrokerClient) Execute(_ context.Context, request model.ExecuteRequest) (model.ExecuteResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.executes = append(client.executes, request)
	return client.executeResult, client.err
}

func (client *fakeBrokerClient) ExecuteApproved(_ context.Context, request model.ApprovedRequest) (model.ExecuteResult, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.approved = append(client.approved, request)
	return client.approvedResult, client.err
}

func TestToolsExposeOnlyPublicSchemas(t *testing.T) {
	client := &fakeBrokerClient{}
	session := connectMCP(t, mcpserver.New(client))
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(listed.Tools))
	properties := make(map[string]bool)
	var approvedProperties []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
		collectSchemaProperties(t, tool.InputSchema, properties)
		collectSchemaProperties(t, tool.OutputSchema, properties)
		if tool.Name == "ssh_execute_approved" {
			approvedProperties = directSchemaProperties(t, tool.InputSchema)
		}
		if tool.Description == "" || !strings.Contains(strings.ToLower(tool.Description), "credential") {
			t.Fatalf("tool %q lacks credential boundary description: %q", tool.Name, tool.Description)
		}
	}
	sort.Strings(names)
	wantNames := []string{"get_ssh_broker_status", "list_ssh_servers", "ssh_execute", "ssh_execute_approved"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("tool names = %v, want %v", names, wantNames)
	}
	for _, forbidden := range []string{"password", "host", "host_fingerprint", "username", "port"} {
		if properties[forbidden] {
			t.Fatalf("tool schema exposed property %q", forbidden)
		}
	}
	if want := []string{"approval_code", "approval_id"}; !slices.Equal(approvedProperties, want) {
		t.Fatalf("approved input properties = %v, want %v", approvedProperties, want)
	}
}

func TestToolsForwardOnlyTypedPublicInputs(t *testing.T) {
	client := &fakeBrokerClient{
		status:  model.BrokerStatus{DaemonReachable: true, Version: "test"},
		servers: []model.ServerSummary{{Alias: "prod", Description: "production", Available: true}},
		executeResult: model.ExecuteResult{
			Status: model.StatusCompleted, Stdout: "ok", ExitCode: 0,
		},
		approvedResult: model.ExecuteResult{Status: model.StatusCompleted, Stdout: "approved"},
	}
	session := connectMCP(t, mcpserver.New(client))
	ctx := context.Background()
	for _, call := range []*mcp.CallToolParams{
		{Name: "get_ssh_broker_status"},
		{Name: "list_ssh_servers"},
		{Name: "ssh_execute", Arguments: map[string]any{
			"server_alias": "prod", "command": "uptime", "timeout_seconds": 9, "max_output_bytes": 4096,
		}},
		{Name: "ssh_execute_approved", Arguments: map[string]any{
			"approval_id": "approval-id", "approval_code": "ABCD",
		}},
	} {
		result, err := session.CallTool(ctx, call)
		if err != nil || result.IsError || result.StructuredContent == nil || len(result.Content) == 0 {
			t.Fatalf("CallTool(%s) = %+v, %v", call.Name, result, err)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.statusCalls != 1 || client.listCalls != 1 || len(client.executes) != 1 || len(client.approved) != 1 {
		t.Fatalf("calls: status=%d list=%d execute=%d approved=%d", client.statusCalls, client.listCalls, len(client.executes), len(client.approved))
	}
	wantExecute := model.ExecuteRequest{ServerAlias: "prod", Command: "uptime", TimeoutSeconds: 9, MaxOutputBytes: 4096}
	if client.executes[0] != wantExecute {
		t.Fatalf("Execute request = %+v, want %+v", client.executes[0], wantExecute)
	}
	if wantApproved := (model.ApprovedRequest{ApprovalID: "approval-id", ApprovalCode: "ABCD"}); client.approved[0] != wantApproved {
		t.Fatalf("ExecuteApproved request = %+v, want %+v", client.approved[0], wantApproved)
	}
}

func TestSensitiveResultIsStructuredAndActionable(t *testing.T) {
	client := &fakeBrokerClient{executeResult: model.ExecuteResult{
		Status: model.StatusRequiresApproval,
		Approval: &model.ApprovalInfo{
			ID: "approval-id", Code: "ABCD", Message: "检测到风险。请由用户确认后回复：允许 ABCD",
		},
	}}
	session := connectMCP(t, mcpserver.New(client))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ssh_execute", Arguments: map[string]any{"server_alias": "prod", "command": "ip route"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || result.StructuredContent == nil {
		t.Fatalf("approval result = %+v", result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if text != client.executeResult.Approval.Message {
		t.Fatalf("approval text = %q, want verbatim %q", text, client.executeResult.Approval.Message)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"requires_approval", "approval-id", "ABCD"} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("structured result missing %q: %s", want, encoded)
		}
	}
}

func TestFailedExecutionIsToolErrorWithStructuredResult(t *testing.T) {
	client := &fakeBrokerClient{executeResult: model.ExecuteResult{
		Status: model.StatusFailed, Error: model.ErrAuthentication,
	}}
	session := connectMCP(t, mcpserver.New(client))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ssh_execute", Arguments: map[string]any{"server_alias": "prod", "command": "uptime"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.StructuredContent == nil {
		t.Fatalf("failed execution result = %+v", result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "authentication failed") {
		t.Fatalf("failed execution text = %q", text)
	}
}

func TestBrokerUnavailableReturnsSanitizedToolError(t *testing.T) {
	client := &fakeBrokerClient{err: fmt.Errorf("dial /Users/test/.aegis-ssh/run/aegis.sock secret-host: %w", broker.ErrUnavailable)}
	session := connectMCP(t, mcpserver.New(client))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_ssh_broker_status"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("result = %+v, want tool error", result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(strings.ToLower(text), "start") || strings.Contains(text, ".aegis-ssh") || strings.Contains(text, "secret-host") {
		t.Fatalf("unsafe unavailable error = %q", text)
	}
}

func TestLockedVaultReturnsActionableSanitizedToolError(t *testing.T) {
	client := &fakeBrokerClient{err: fmt.Errorf("vault.enc at secret-path: %w", model.ErrLockedVault)}
	session := connectMCP(t, mcpserver.New(client))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_ssh_servers"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("result = %+v, want tool error", result)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(strings.ToLower(text), "unlock") || strings.Contains(text, "vault.enc") || strings.Contains(text, "secret-path") {
		t.Fatalf("unsafe locked-vault error = %q", text)
	}
}

func TestNilClientAndUnknownDependencyErrorsStaySanitized(t *testing.T) {
	tests := []struct {
		name   string
		server *mcpserver.Server
	}{
		{name: "nil client", server: mcpserver.New(nil)},
		{name: "unknown dependency error", server: mcpserver.New(&fakeBrokerClient{
			err: errors.New("secret-host /Users/test/.aegis-ssh/run/aegis.sock"),
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := connectMCP(t, test.server)
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_ssh_broker_status"})
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("result = %+v, want tool error", result)
			}
			text := result.Content[0].(*mcp.TextContent).Text
			if strings.Contains(text, "secret-host") || strings.Contains(text, ".aegis-ssh") {
				t.Fatalf("unsafe tool error = %q", text)
			}
		})
	}
}

func TestApprovedToolRejectsCommandReplacementBeforeBrokerCall(t *testing.T) {
	client := &fakeBrokerClient{}
	session := connectMCP(t, mcpserver.New(client))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "ssh_execute_approved", Arguments: map[string]any{
			"approval_id": "approval-id", "approval_code": "ABCD", "command": "replacement",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("result = %+v, want schema error", result)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.approved) != 0 {
		t.Fatalf("broker received %d approved calls", len(client.approved))
	}
}

func connectMCP(t *testing.T, server *mcpserver.Server) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		cancel()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("MCP server stopped with %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("MCP server did not stop")
		}
	})
	return session
}

func collectSchemaProperties(t *testing.T, schema any, result map[string]bool) {
	t.Helper()
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		if properties, ok := object["properties"].(map[string]any); ok {
			for name, property := range properties {
				result[name] = true
				walk(property)
			}
		}
		if items, ok := object["items"]; ok {
			walk(items)
		}
	}
	walk(root)
}

func directSchemaProperties(t *testing.T, schema any) []string {
	t.Helper()
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	result := make([]string, 0, len(root.Properties))
	for name := range root.Properties {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
