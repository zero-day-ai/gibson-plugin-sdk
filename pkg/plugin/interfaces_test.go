package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlugin implements SecurityPlugin for testing
type TestPlugin struct {
	*BasePlugin
}

func (tp *TestPlugin) Execute(ctx context.Context, request *AssessRequest) models.Result[*AssessResponse] {
	return models.Ok(&AssessResponse{
		Success:   true,
		Completed: true,
		Findings:  []*Finding{},
		StartTime: time.Now(),
		EndTime:   time.Now(),
		RequestID: request.RequestID,
		ScanID:    request.ScanID,
	})
}

func TestBasePlugin_GetInfo(t *testing.T) {
	pluginInfo := &PluginInfo{
		Name:        "test-plugin",
		Version:     "1.0.0",
		Description: "Test plugin",
		Author:      "Test Author",
		Domains:     []SecurityDomain{DomainInterface},
	}

	basePlugin := NewBasePlugin(pluginInfo)
	result := basePlugin.GetInfo(context.Background())

	require.True(t, result.IsOk())
	info := result.Unwrap()
	assert.Equal(t, "test-plugin", info.Name)
	assert.Equal(t, "1.0.0", info.Version)
}

func TestBasePlugin_GetInfo_NotInitialized(t *testing.T) {
	basePlugin := &BasePlugin{}
	result := basePlugin.GetInfo(context.Background())

	require.True(t, result.IsErr())
	assert.Equal(t, ErrPluginNotInitialized, result.Error())
}

func TestBasePlugin_Health(t *testing.T) {
	basePlugin := NewBasePlugin(&PluginInfo{Name: "test"})
	result := basePlugin.Health(context.Background())

	require.True(t, result.IsOk())
	health := result.Unwrap()
	assert.Equal(t, HealthStatusHealthy, health.Status)
	assert.Equal(t, "Plugin is healthy", health.Message)
}

func TestBasePlugin_Validate(t *testing.T) {
	basePlugin := NewBasePlugin(&PluginInfo{Name: "test"})

	tests := []struct {
		name        string
		request     *AssessRequest
		expectValid bool
		expectMsg   string
	}{
		{
			name:        "nil request",
			request:     nil,
			expectValid: false,
			expectMsg:   "request cannot be nil",
		},
		{
			name: "nil target",
			request: &AssessRequest{
				Target: nil,
			},
			expectValid: false,
			expectMsg:   "target cannot be nil",
		},
		{
			name: "empty target name",
			request: &AssessRequest{
				Target: &Target{Name: ""},
			},
			expectValid: false,
			expectMsg:   "target name cannot be empty",
		},
		{
			name: "valid request",
			request: &AssessRequest{
				Target: &Target{
					ID:   "test-target",
					Name: "Test Target",
					Type: "api",
				},
			},
			expectValid: true,
			expectMsg:   "request is valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := basePlugin.Validate(context.Background(), tt.request)
			require.True(t, result.IsOk())

			validation := result.Unwrap()
			assert.Equal(t, tt.expectValid, validation.Valid)
			assert.Equal(t, tt.expectMsg, validation.Message)
		})
	}
}

func TestBasePlugin_Config(t *testing.T) {
	basePlugin := NewBasePlugin(&PluginInfo{Name: "test"})

	// Test getting empty config
	result := basePlugin.GetCurrentConfig(context.Background())
	require.True(t, result.IsOk())
	config := result.Unwrap()
	assert.Empty(t, config)

	// Test updating config
	newConfig := map[string]interface{}{
		"timeout": 30,
		"retries": 3,
		"enabled": true,
	}

	updateResult := basePlugin.UpdateConfig(context.Background(), newConfig)
	require.True(t, updateResult.IsOk())
	assert.True(t, updateResult.Unwrap())

	// Test getting updated config
	result = basePlugin.GetCurrentConfig(context.Background())
	require.True(t, result.IsOk())
	config = result.Unwrap()
	assert.Equal(t, newConfig, config)

	// Test nil config
	updateResult = basePlugin.UpdateConfig(context.Background(), nil)
	require.True(t, updateResult.IsErr())
	assert.Equal(t, ErrInvalidConfig, updateResult.Error())
}

func TestTestPlugin_Execute(t *testing.T) {
	pluginInfo := &PluginInfo{
		Name:    "test-plugin",
		Version: "1.0.0",
		Domains: []SecurityDomain{DomainInterface},
	}

	testPlugin := &TestPlugin{
		BasePlugin: NewBasePlugin(pluginInfo),
	}

	request := &AssessRequest{
		Target: &Target{
			ID:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		RequestID: "test-request-123",
		ScanID:    "test-scan-456",
		Timeout:   30 * time.Second,
	}

	result := testPlugin.Execute(context.Background(), request)
	require.True(t, result.IsOk())

	response := result.Unwrap()
	assert.True(t, response.Success)
	assert.True(t, response.Completed)
	assert.Empty(t, response.Findings)
	assert.Equal(t, "test-request-123", response.RequestID)
	assert.Equal(t, "test-scan-456", response.ScanID)
}

func TestSecurityDomains(t *testing.T) {
	expectedDomains := []SecurityDomain{
		DomainModel,
		DomainData,
		DomainInterface,
		DomainInfrastructure,
		DomainOutput,
		DomainProcess,
	}

	expectedValues := []string{
		"model",
		"data",
		"interface",
		"infrastructure",
		"output",
		"process",
	}

	for i, domain := range expectedDomains {
		assert.Equal(t, expectedValues[i], string(domain))
	}
}

func TestSeverityLevels(t *testing.T) {
	severities := []SeverityLevel{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}

	expectedValues := []string{
		"critical",
		"high",
		"medium",
		"low",
		"info",
	}

	for i, severity := range severities {
		assert.Equal(t, expectedValues[i], string(severity))
	}
}

func TestConfidenceLevels(t *testing.T) {
	confidences := []ConfidenceLevel{
		ConfidenceHigh,
		ConfidenceMedium,
		ConfidenceLow,
	}

	expectedValues := []string{
		"high",
		"medium",
		"low",
	}

	for i, confidence := range confidences {
		assert.Equal(t, expectedValues[i], string(confidence))
	}
}
