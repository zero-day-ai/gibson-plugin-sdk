package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/grpc/proto"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

// MockPlugin for testing
type MockGRPCPlugin struct {
	infoResult     models.Result[*plugin.PluginInfo]
	executeResult  models.Result[*plugin.AssessResponse]
	validateResult models.Result[*plugin.ValidationResult]
	healthResult   models.Result[*plugin.HealthStatus]
}

func NewMockGRPCPlugin() *MockGRPCPlugin {
	return &MockGRPCPlugin{
		infoResult: models.Ok(&plugin.PluginInfo{
			Name:    "test-plugin",
			Version: "1.0.0",
			Domain:  plugin.DomainInterface,
		}),
		executeResult: models.Ok(&plugin.AssessResponse{
			Success:   true,
			Completed: true,
			Findings:  []*plugin.Finding{},
			RequestID: "test-request",
		}),
		validateResult: models.Ok(&plugin.ValidationResult{
			Valid:   true,
			Message: "validation passed",
		}),
		healthResult: models.Ok(&plugin.HealthStatus{
			Status:    plugin.HealthStatusHealthy,
			Message:   "plugin is healthy",
			Timestamp: time.Now(),
		}),
	}
}

func (m *MockGRPCPlugin) GetInfo(ctx context.Context) models.Result[*plugin.PluginInfo] {
	return m.infoResult
}

func (m *MockGRPCPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
	return m.executeResult
}

func (m *MockGRPCPlugin) Validate(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.ValidationResult] {
	return m.validateResult
}

func (m *MockGRPCPlugin) Health(ctx context.Context) models.Result[*plugin.HealthStatus] {
	return m.healthResult
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func setupTestServer(t *testing.T, mockPlugin *MockGRPCPlugin) *grpc.ClientConn {
	lis = bufconn.Listen(bufSize)

	server := grpc.NewServer()
	grpcServer := NewGRPCServer(mockPlugin)
	proto.RegisterSecurityPluginServer(server, grpcServer)

	go func() {
		if err := server.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
		server.Stop()
		lis.Close()
	})

	return conn
}

func TestNewGRPCClient(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(t, mockPlugin)

	client := NewGRPCClient(conn)
	assert.NotNil(t, client)
	assert.NotNil(t, client.client)
}

func TestGRPCClient_GetInfo(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(t, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	result := client.GetInfo(ctx)
	assert.True(t, result.IsOk())

	info := result.Unwrap()
	assert.Equal(t, "test-plugin", info.Name)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, plugin.DomainInterface, info.Domain)
}

func TestGRPCClient_GetInfo_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.infoResult = models.Err[*plugin.PluginInfo](assert.AnError)

	conn := setupTestServer(t, mockPlugin)
	client := NewGRPCClient(conn)
	ctx := context.Background()

	result := client.GetInfo(ctx)
	assert.True(t, result.IsErr())
	assert.NotNil(t, result.Error())
}

func TestGRPCClient_Execute(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(t, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "test-request",
		Target: &plugin.Target{
			ID:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain:         plugin.DomainInterface,
			MaxFindings:    10,
			TimeoutSeconds: 30,
		},
	}

	result := client.Execute(ctx, request)
	assert.True(t, result.IsOk())

	response := result.Unwrap()
	assert.True(t, response.Success)
	assert.True(t, response.Completed)
	assert.Equal(t, "test-request", response.RequestID)
}

func TestGRPCClient_Execute_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.executeResult = models.Err[*plugin.AssessResponse](assert.AnError)

	conn := setupTestServer(t, mockPlugin)
	client := NewGRPCClient(conn)
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "test-request",
		Target: &plugin.Target{
			ID:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	result := client.Execute(ctx, request)
	assert.True(t, result.IsErr())
	assert.NotNil(t, result.Error())
}

func TestGRPCClient_Validate(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(t, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "test-request",
		Target: &plugin.Target{
			ID:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	result := client.Validate(ctx, request)
	assert.True(t, result.IsOk())

	validation := result.Unwrap()
	assert.True(t, validation.Valid)
	assert.Equal(t, "validation passed", validation.Message)
}

func TestGRPCClient_Validate_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.validateResult = models.Err[*plugin.ValidationResult](assert.AnError)

	conn := setupTestServer(t, mockPlugin)
	client := NewGRPCClient(conn)
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "test-request",
		Target: &plugin.Target{
			ID:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	result := client.Validate(ctx, request)
	assert.True(t, result.IsErr())
	assert.NotNil(t, result.Error())
}

func TestGRPCClient_Health(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(t, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	result := client.Health(ctx)
	assert.True(t, result.IsOk())

	health := result.Unwrap()
	assert.Equal(t, plugin.HealthStatusHealthy, health.Status)
	assert.Equal(t, "plugin is healthy", health.Message)
	assert.False(t, health.Timestamp.IsZero())
}

func TestGRPCClient_Health_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.healthResult = models.Err[*plugin.HealthStatus](assert.AnError)

	conn := setupTestServer(t, mockPlugin)
	client := NewGRPCClient(conn)
	ctx := context.Background()

	result := client.Health(ctx)
	assert.True(t, result.IsErr())
	assert.NotNil(t, result.Error())
}

func TestGRPCClient_Timeout(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(t, mockPlugin)

	client := NewGRPCClient(conn)

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	// Wait a bit to ensure timeout
	time.Sleep(time.Millisecond)

	result := client.GetInfo(ctx)
	assert.True(t, result.IsErr())
	assert.Contains(t, result.Error().Error(), "context deadline exceeded")
}

func TestGRPCClient_ConnectionError(t *testing.T) {
	// Create a client with no server
	conn, err := grpc.Dial("localhost:99999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewGRPCClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result := client.GetInfo(ctx)
	assert.True(t, result.IsErr())
	assert.NotNil(t, result.Error())
}

// Benchmark tests
func BenchmarkGRPCClient_GetInfo(b *testing.B) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(b, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := client.GetInfo(ctx)
		if result.IsErr() {
			b.Fatal(result.Error())
		}
	}
}

func BenchmarkGRPCClient_Execute(b *testing.B) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(b, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "test-request",
		Target: &plugin.Target{
			ID:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := client.Execute(ctx, request)
		if result.IsErr() {
			b.Fatal(result.Error())
		}
	}
}

func BenchmarkGRPCClient_Health(b *testing.B) {
	mockPlugin := NewMockGRPCPlugin()
	conn := setupTestServer(b, mockPlugin)

	client := NewGRPCClient(conn)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := client.Health(ctx)
		if result.IsErr() {
			b.Fatal(result.Error())
		}
	}
}
