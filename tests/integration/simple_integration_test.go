//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/zero-day-ai/gibson-sdk/pkg/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SimpleTestPlugin is a minimal test plugin
type SimpleTestPlugin struct {
	*plugin.BasePlugin
	executionCount int
}

func NewSimpleTestPlugin() *SimpleTestPlugin {
	info := &plugin.PluginInfo{
		Name:        "simple-test-plugin",
		Version:     "1.0.0",
		Description: "Simple plugin for integration testing",
		Author:      "Test Team",
		Domain:      plugin.DomainInterface,
		SupportedPayloadTypes: []plugin.PayloadType{
			plugin.PayloadTypeInput,
		},
		Capabilities: &plugin.PluginCapabilities{
			SupportsStreaming:     false,
			SupportsBatch:         false,
			SupportsConcurrent:    true,
			MaxConcurrentRequests: 5,
			TimeoutSeconds:        30,
		},
	}

	return &SimpleTestPlugin{
		BasePlugin: plugin.NewBasePlugin(info),
	}
}

func (p *SimpleTestPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
	p.executionCount++

	// Basic validation
	if request == nil {
		return models.Ok(&plugin.AssessResponse{
			Success: false,
			Error:   "request cannot be nil",
		})
	}

	if request.Target == nil {
		return models.Ok(&plugin.AssessResponse{
			Success: false,
			Error:   "target cannot be nil",
		})
	}

	// Simulate some processing time
	time.Sleep(1 * time.Millisecond)

	// Create a simple finding
	finding := &plugin.Finding{
		ID:          "simple-finding-1",
		Title:       "Test Finding",
		Description: "This is a test finding from the simple plugin",
		Severity:    plugin.SeverityMedium,
		Domain:      plugin.DomainInterface,
		PayloadType: plugin.PayloadTypeInput,
		DiscoveredAt: time.Now(),
	}

	response := &plugin.AssessResponse{
		Success:   true,
		Completed: true,
		Findings:  []*plugin.Finding{finding},
		StartTime: time.Now().Add(-1 * time.Millisecond),
		EndTime:   time.Now(),
		Duration:  1 * time.Millisecond,
		RequestID: request.RequestID,
		ResourceUsage: &plugin.ResourceUsage{
			CPUTime:    1 * time.Millisecond,
			Memory:     1024, // 1KB
			Goroutines: 1,
		},
	}

	return models.Ok(response)
}

func TestSimpleIntegration_BasicWorkflow(t *testing.T) {
	plugin := NewSimpleTestPlugin()
	ctx := context.Background()

	// Test GetInfo
	t.Run("GetInfo", func(t *testing.T) {
		result := plugin.GetInfo(ctx)
		require.True(t, result.IsOk())

		info := result.Unwrap()
		assert.Equal(t, "simple-test-plugin", info.Name)
		assert.Equal(t, "1.0.0", info.Version)
	})

	// Test Health
	t.Run("Health", func(t *testing.T) {
		result := plugin.Health(ctx)
		require.True(t, result.IsOk())

		health := result.Unwrap()
		assert.Equal(t, plugin.HealthStatusHealthy, health.Status)
	})

	// Test Execute
	t.Run("Execute", func(t *testing.T) {
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

		result := plugin.Execute(ctx, request)
		require.True(t, result.IsOk())

		response := result.Unwrap()
		assert.True(t, response.Success)
		assert.Len(t, response.Findings, 1)
		assert.Equal(t, "test-request", response.RequestID)
	})
}

func TestSimpleIntegration_Validation(t *testing.T) {
	validator := validation.NewValidator()

	// Test plugin info validation
	plugin := NewSimpleTestPlugin()
	infoResult := plugin.GetInfo(context.Background())
	require.True(t, infoResult.IsOk())

	info := infoResult.Unwrap()
	validationResult := validator.ValidatePluginInfo(info)
	assert.False(t, validationResult.HasErrors())

	// Test request validation
	request := &plugin.AssessRequest{
		RequestID: "validation-test",
		Target: &plugin.Target{
			ID:   "validation-target",
			Name: "Validation Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	validationResult = validator.ValidateAssessRequest(request)
	assert.False(t, validationResult.HasErrors())
}

func TestSimpleIntegration_ConcurrentExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	plugin := NewSimpleTestPlugin()
	ctx := context.Background()

	numGoroutines := 3
	resultChan := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			request := &plugin.AssessRequest{
				RequestID: "concurrent-" + string(rune(id)),
				Target: &plugin.Target{
					ID:   "concurrent-target",
					Name: "Concurrent Target",
					Type: "api",
				},
				Config: &plugin.AssessmentConfig{
					Domain: plugin.DomainInterface,
				},
			}

			result := plugin.Execute(ctx, request)
			resultChan <- result.IsOk() && result.Unwrap().Success
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		if <-resultChan {
			successCount++
		}
	}

	assert.Equal(t, numGoroutines, successCount)
}

func TestSimpleIntegration_ErrorHandling(t *testing.T) {
	plugin := NewSimpleTestPlugin()
	ctx := context.Background()

	// Test with nil request
	result := plugin.Execute(ctx, nil)
	require.True(t, result.IsOk())

	response := result.Unwrap()
	assert.False(t, response.Success)
	assert.Contains(t, response.Error, "cannot be nil")

	// Test with nil target
	request := &plugin.AssessRequest{
		RequestID: "error-test",
		Target:    nil,
	}

	result = plugin.Execute(ctx, request)
	require.True(t, result.IsOk())

	response = result.Unwrap()
	assert.False(t, response.Success)
	assert.Contains(t, response.Error, "target cannot be nil")
}

func BenchmarkSimpleIntegration_Execute(b *testing.B) {
	plugin := NewSimpleTestPlugin()
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
		result := plugin.Execute(ctx, request)
		if result.IsErr() {
			b.Fatal(result.Error())
		}
	}
}