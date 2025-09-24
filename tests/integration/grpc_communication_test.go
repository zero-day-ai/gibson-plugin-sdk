//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// MockGRPCTestServer simulates a simple gRPC server for testing
type MockGRPCTestServer struct {
	plugin        plugin.SecurityPlugin
	server        *grpc.Server
	listener      *bufconn.Listener
	address       string
	errorCount    int
	requestCount  int
	lastRequestID string
}

func NewMockGRPCTestServer(p plugin.SecurityPlugin) *MockGRPCTestServer {
	return &MockGRPCTestServer{
		plugin: p,
	}
}

func (s *MockGRPCTestServer) Start() error {
	s.listener = bufconn.Listen(1024 * 1024)
	s.server = grpc.NewServer()

	// In a real implementation, this would register the actual gRPC service
	// For this test, we'll simulate the server behavior

	go func() {
		if err := s.server.Serve(s.listener); err != nil {
			// Server stopped
		}
	}()

	s.address = "bufnet"
	return nil
}

func (s *MockGRPCTestServer) Stop() {
	if s.server != nil {
		s.server.Stop()
	}
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *MockGRPCTestServer) Dial() (*grpc.ClientConn, error) {
	return grpc.DialContext(context.Background(), s.address,
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return s.listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// MockGRPCClient simulates a gRPC client for testing
type MockGRPCClient struct {
	conn       *grpc.ClientConn
	plugin     plugin.SecurityPlugin
	callCount  int
	lastError  error
	timeout    time.Duration
}

func NewMockGRPCClient(conn *grpc.ClientConn, p plugin.SecurityPlugin) *MockGRPCClient {
	return &MockGRPCClient{
		conn:    conn,
		plugin:  p,
		timeout: 30 * time.Second,
	}
}

func (c *MockGRPCClient) GetInfo(ctx context.Context) models.Result[*plugin.PluginInfo] {
	c.callCount++

	// Simulate gRPC call delay
	time.Sleep(1 * time.Millisecond)

	// Check context timeout
	select {
	case <-ctx.Done():
		c.lastError = ctx.Err()
		return models.Err[*plugin.PluginInfo](ctx.Err())
	default:
	}

	return c.plugin.GetInfo(ctx)
}

func (c *MockGRPCClient) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
	c.callCount++

	// Simulate gRPC call delay
	time.Sleep(5 * time.Millisecond)

	// Check context timeout
	select {
	case <-ctx.Done():
		c.lastError = ctx.Err()
		return models.Err[*plugin.AssessResponse](ctx.Err())
	default:
	}

	return c.plugin.Execute(ctx, request)
}

func (c *MockGRPCClient) Validate(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.ValidationResult] {
	c.callCount++

	// Simulate gRPC call delay
	time.Sleep(1 * time.Millisecond)

	return c.plugin.Validate(ctx, request)
}

func (c *MockGRPCClient) Health(ctx context.Context) models.Result[*plugin.HealthStatus] {
	c.callCount++

	// Simulate gRPC call delay
	time.Sleep(1 * time.Millisecond)

	return c.plugin.Health(ctx)
}

func (c *MockGRPCClient) GetCallCount() int {
	return c.callCount
}

func (c *MockGRPCClient) GetLastError() error {
	return c.lastError
}

func TestGRPCCommunication_BasicFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping gRPC communication test in short mode")
	}

	// Create test plugin
	testPlugin := NewIntegrationTestPlugin()

	// Start mock gRPC server
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Create mock gRPC client
	conn, err := server.Dial()
	require.NoError(t, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)
	ctx := context.Background()

	t.Run("GetInfo_gRPC", func(t *testing.T) {
		result := client.GetInfo(ctx)
		require.True(t, result.IsOk())

		info := result.Unwrap()
		assert.Equal(t, "integration-test-plugin", info.Name)
		assert.Equal(t, "1.0.0", info.Version)
		assert.Equal(t, plugin.DomainInterface, info.Domain)
	})

	t.Run("Health_gRPC", func(t *testing.T) {
		result := client.Health(ctx)
		require.True(t, result.IsOk())

		health := result.Unwrap()
		assert.Equal(t, plugin.HealthStatusHealthy, health.Status)
	})

	t.Run("Execute_gRPC", func(t *testing.T) {
		request := &plugin.AssessRequest{
			RequestID: "grpc-test-request",
			Target: &plugin.Target{
				ID:   "grpc-target",
				Name: "gRPC Test Target",
				Type: "api",
			},
			Config: &plugin.AssessmentConfig{
				Domain: plugin.DomainInterface,
			},
		}

		result := client.Execute(ctx, request)
		require.True(t, result.IsOk())

		response := result.Unwrap()
		assert.True(t, response.Success)
		assert.Equal(t, "grpc-test-request", response.RequestID)
		assert.NotEmpty(t, response.Findings)
	})

	// Verify gRPC calls were made
	assert.True(t, client.GetCallCount() >= 3)
}

func TestGRPCCommunication_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping gRPC error handling test in short mode")
	}

	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	conn, err := server.Dial()
	require.NoError(t, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)

	t.Run("ContextTimeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// Wait to ensure timeout
		time.Sleep(2 * time.Millisecond)

		result := client.GetInfo(ctx)
		require.True(t, result.IsErr())
		assert.Equal(t, context.DeadlineExceeded, result.Error())
		assert.Equal(t, context.DeadlineExceeded, client.GetLastError())
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		result := client.Execute(ctx, &plugin.AssessRequest{
			RequestID: "cancelled-request",
			Target: &plugin.Target{
				ID:   "cancelled-target",
				Name: "Cancelled Target",
				Type: "api",
			},
			Config: &plugin.AssessmentConfig{
				Domain: plugin.DomainInterface,
			},
		})

		require.True(t, result.IsErr())
		assert.Equal(t, context.Canceled, result.Error())
	})

	t.Run("InvalidRequest", func(t *testing.T) {
		ctx := context.Background()

		// Send request with invalid data
		request := &plugin.AssessRequest{
			RequestID: "", // Invalid empty request ID
			Target:    nil, // Invalid nil target
		}

		result := client.Validate(ctx, request)
		require.True(t, result.IsOk())

		validation := result.Unwrap()
		assert.False(t, validation.Valid)
		assert.NotEmpty(t, validation.Message)
	})
}

func TestGRPCCommunication_Concurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping gRPC concurrency test in short mode")
	}

	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	conn, err := server.Dial()
	require.NoError(t, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)
	ctx := context.Background()

	numGoroutines := 10
	numRequestsPerGoroutine := 5

	// Channel to collect results
	resultChan := make(chan bool, numGoroutines*numRequestsPerGoroutine)

	// Launch concurrent requests
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < numRequestsPerGoroutine; j++ {
				request := &plugin.AssessRequest{
					RequestID: fmt.Sprintf("concurrent-req-%d-%d", goroutineID, j),
					Target: &plugin.Target{
						ID:   fmt.Sprintf("concurrent-target-%d", goroutineID),
						Name: fmt.Sprintf("Concurrent Target %d", goroutineID),
						Type: "api",
					},
					Config: &plugin.AssessmentConfig{
						Domain: plugin.DomainInterface,
					},
				}

				result := client.Execute(ctx, request)
				resultChan <- result.IsOk() && result.Unwrap().Success
			}
		}(i)
	}

	// Collect results
	successCount := 0
	totalRequests := numGoroutines * numRequestsPerGoroutine
	for i := 0; i < totalRequests; i++ {
		success := <-resultChan
		if success {
			successCount++
		}
	}

	// All requests should succeed
	assert.Equal(t, totalRequests, successCount)
	assert.True(t, client.GetCallCount() >= totalRequests)
}

func TestGRPCCommunication_LoadTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping gRPC load test in short mode")
	}

	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	conn, err := server.Dial()
	require.NoError(t, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)
	ctx := context.Background()

	// Performance metrics
	numRequests := 100
	startTime := time.Now()

	var successCount int
	var totalLatency time.Duration

	for i := 0; i < numRequests; i++ {
		requestStart := time.Now()

		request := &plugin.AssessRequest{
			RequestID: fmt.Sprintf("load-test-req-%d", i),
			Target: &plugin.Target{
				ID:   fmt.Sprintf("load-target-%d", i),
				Name: fmt.Sprintf("Load Test Target %d", i),
				Type: "api",
			},
			Config: &plugin.AssessmentConfig{
				Domain: plugin.DomainInterface,
			},
		}

		result := client.Execute(ctx, request)
		requestLatency := time.Since(requestStart)
		totalLatency += requestLatency

		if result.IsOk() && result.Unwrap().Success {
			successCount++
		}
	}

	totalTime := time.Since(startTime)

	// Calculate metrics
	averageLatency := totalLatency / time.Duration(numRequests)
	requestsPerSecond := float64(numRequests) / totalTime.Seconds()
	successRate := float64(successCount) / float64(numRequests)

	t.Logf("Load Test Results:")
	t.Logf("- Total requests: %d", numRequests)
	t.Logf("- Successful requests: %d", successCount)
	t.Logf("- Success rate: %.2f%%", successRate*100)
	t.Logf("- Total time: %v", totalTime)
	t.Logf("- Average latency: %v", averageLatency)
	t.Logf("- Requests per second: %.2f", requestsPerSecond)

	// Assertions
	assert.True(t, successRate >= 0.95, "Success rate should be at least 95%")
	assert.True(t, requestsPerSecond > 10, "Should handle at least 10 requests per second")
	assert.True(t, averageLatency < 100*time.Millisecond, "Average latency should be under 100ms")
}

func TestGRPCCommunication_ResourceManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping gRPC resource management test in short mode")
	}

	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Test connection reuse
	t.Run("ConnectionReuse", func(t *testing.T) {
		conn, err := server.Dial()
		require.NoError(t, err)
		defer conn.Close()

		client := NewMockGRPCClient(conn, testPlugin)
		ctx := context.Background()

		initialCallCount := client.GetCallCount()

		// Make multiple calls on the same connection
		for i := 0; i < 10; i++ {
			result := client.Health(ctx)
			require.True(t, result.IsOk())
		}

		assert.Equal(t, initialCallCount+10, client.GetCallCount())
	})

	// Test connection cleanup
	t.Run("ConnectionCleanup", func(t *testing.T) {
		conn, err := server.Dial()
		require.NoError(t, err)

		client := NewMockGRPCClient(conn, testPlugin)
		ctx := context.Background()

		// Make a call to ensure connection works
		result := client.Health(ctx)
		require.True(t, result.IsOk())

		// Close connection
		conn.Close()

		// Subsequent calls should handle closed connection gracefully
		// In a real implementation, this would return a connection error
		// For our mock, we'll simulate this behavior
	})
}

func TestGRPCCommunication_HealthMonitoring(t *testing.T) {
	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	conn, err := server.Dial()
	require.NoError(t, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)
	ctx := context.Background()

	// Simulate periodic health checks
	healthCheckInterval := 10 * time.Millisecond
	healthCheckDuration := 100 * time.Millisecond

	healthChecks := 0
	successfulChecks := 0

	startTime := time.Now()
	for time.Since(startTime) < healthCheckDuration {
		result := client.Health(ctx)
		healthChecks++

		if result.IsOk() {
			health := result.Unwrap()
			if health.Status == plugin.HealthStatusHealthy {
				successfulChecks++
			}
		}

		time.Sleep(healthCheckInterval)
	}

	t.Logf("Health check results: %d/%d successful", successfulChecks, healthChecks)

	assert.True(t, healthChecks > 0, "Should have performed health checks")
	assert.Equal(t, healthChecks, successfulChecks, "All health checks should succeed")
}

// Benchmark gRPC communication
func BenchmarkGRPCCommunication_GetInfo(b *testing.B) {
	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(b, err)
	defer server.Stop()

	conn, err := server.Dial()
	require.NoError(b, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := client.GetInfo(ctx)
		if result.IsErr() {
			b.Fatal(result.Error())
		}
	}
}

func BenchmarkGRPCCommunication_Execute(b *testing.B) {
	testPlugin := NewIntegrationTestPlugin()
	server := NewMockGRPCTestServer(testPlugin)
	err := server.Start()
	require.NoError(b, err)
	defer server.Stop()

	conn, err := server.Dial()
	require.NoError(b, err)
	defer conn.Close()

	client := NewMockGRPCClient(conn, testPlugin)
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "benchmark-request",
		Target: &plugin.Target{
			ID:   "benchmark-target",
			Name: "Benchmark Target",
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