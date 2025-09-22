package testing

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/google/uuid"
)

// MockPlugin is a test implementation of the SecurityPlugin interface
type MockPlugin struct {
	// Configuration
	name        string
	version     string
	domain      plugin.SecurityDomain
	description string

	// Behavior control
	shouldFail        bool
	failureMessage    string
	executionDuration time.Duration
	findings          []models.Finding

	// Call tracking
	initializeCalled bool
	validateCalled   bool
	executeCalled    bool
	cleanupCalled    bool
	lastRequest      *models.AssessRequest
}

// NewMockPlugin creates a new mock plugin with default configuration
func NewMockPlugin() *MockPlugin {
	return &MockPlugin{
		name:              "mock-plugin",
		version:           "1.0.0",
		domain:            plugin.SecurityDomainInterface,
		description:       "Mock plugin for testing",
		shouldFail:        false,
		executionDuration: 100 * time.Millisecond,
		findings:          []models.Finding{},
	}
}

// NewMockPluginWithConfig creates a mock plugin with custom configuration
func NewMockPluginWithConfig(name, version string, domain plugin.SecurityDomain) *MockPlugin {
	mock := NewMockPlugin()
	mock.name = name
	mock.version = version
	mock.domain = domain
	return mock
}

// Configuration methods for test setup
func (m *MockPlugin) WithFailure(message string) *MockPlugin {
	m.shouldFail = true
	m.failureMessage = message
	return m
}

func (m *MockPlugin) WithDuration(duration time.Duration) *MockPlugin {
	m.executionDuration = duration
	return m
}

func (m *MockPlugin) WithFindings(findings []models.Finding) *MockPlugin {
	m.findings = findings
	return m
}

// SecurityPlugin interface implementation
func (m *MockPlugin) GetInfo() models.Result[models.PluginInfo] {
	info := models.PluginInfo{
		Name:        m.name,
		Version:     m.version,
		Domain:      m.domain,
		Description: m.description,
		Author:      "Test Author",
		License:     "MIT",
		Tags:        []string{"test", "mock"},
	}
	return models.Ok(info)
}

func (m *MockPlugin) Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool] {
	m.initializeCalled = true

	if m.shouldFail {
		return models.Err[bool](fmt.Errorf("initialization failed: %s", m.failureMessage))
	}

	return models.Ok(true)
}

func (m *MockPlugin) Validate(ctx context.Context, request models.AssessRequest) models.Result[bool] {
	m.validateCalled = true
	m.lastRequest = &request

	if m.shouldFail {
		return models.Err[bool](fmt.Errorf("validation failed: %s", m.failureMessage))
	}

	return models.Ok(true)
}

func (m *MockPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
	m.executeCalled = true
	m.lastRequest = &request

	// Simulate execution time
	select {
	case <-time.After(m.executionDuration):
	case <-ctx.Done():
		return models.Err[models.AssessResponse](ctx.Err())
	}

	if m.shouldFail {
		return models.Err[models.AssessResponse](fmt.Errorf("execution failed: %s", m.failureMessage))
	}

	response := models.AssessResponse{
		ID:         uuid.New(),
		PluginName: m.name,
		Status:     "completed",
		StartTime:  time.Now().Add(-m.executionDuration),
		EndTime:    time.Now(),
		Findings:   m.findings,
		Metadata: map[string]interface{}{
			"test_execution": true,
			"duration_ms":    m.executionDuration.Milliseconds(),
		},
	}

	return models.Ok(response)
}

func (m *MockPlugin) Cleanup(ctx context.Context) models.Result[bool] {
	m.cleanupCalled = true

	if m.shouldFail {
		return models.Err[bool](fmt.Errorf("cleanup failed: %s", m.failureMessage))
	}

	return models.Ok(true)
}

// Test helper methods
func (m *MockPlugin) WasInitializeCalled() bool {
	return m.initializeCalled
}

func (m *MockPlugin) WasValidateCalled() bool {
	return m.validateCalled
}

func (m *MockPlugin) WasExecuteCalled() bool {
	return m.executeCalled
}

func (m *MockPlugin) WasCleanupCalled() bool {
	return m.cleanupCalled
}

func (m *MockPlugin) GetLastRequest() *models.AssessRequest {
	return m.lastRequest
}

func (m *MockPlugin) Reset() {
	m.initializeCalled = false
	m.validateCalled = false
	m.executeCalled = false
	m.cleanupCalled = false
	m.lastRequest = nil
	m.shouldFail = false
	m.failureMessage = ""
}

// MockStreamingPlugin implements StreamingPlugin interface for testing
type MockStreamingPlugin struct {
	*MockPlugin
	streamResults []models.StreamResult
}

func NewMockStreamingPlugin() *MockStreamingPlugin {
	return &MockStreamingPlugin{
		MockPlugin:    NewMockPlugin(),
		streamResults: []models.StreamResult{},
	}
}

func (m *MockStreamingPlugin) WithStreamResults(results []models.StreamResult) *MockStreamingPlugin {
	m.streamResults = results
	return m
}

func (m *MockStreamingPlugin) ExecuteStream(ctx context.Context, request models.AssessRequest, resultChan chan<- models.StreamResult) models.Result[bool] {
	m.executeCalled = true
	m.lastRequest = &request

	if m.shouldFail {
		return models.Err[bool](fmt.Errorf("stream execution failed: %s", m.failureMessage))
	}

	// Send mock results
	go func() {
		defer close(resultChan)

		for _, result := range m.streamResults {
			select {
			case resultChan <- result:
				// Add small delay to simulate processing
				time.Sleep(10 * time.Millisecond)
			case <-ctx.Done():
				return
			}
		}
	}()

	return models.Ok(true)
}

// MockBatchPlugin implements BatchPlugin interface for testing
type MockBatchPlugin struct {
	*MockPlugin
	batchResponses []models.AssessResponse
}

func NewMockBatchPlugin() *MockBatchPlugin {
	return &MockBatchPlugin{
		MockPlugin:     NewMockPlugin(),
		batchResponses: []models.AssessResponse{},
	}
}

func (m *MockBatchPlugin) WithBatchResponses(responses []models.AssessResponse) *MockBatchPlugin {
	m.batchResponses = responses
	return m
}

func (m *MockBatchPlugin) ExecuteBatch(ctx context.Context, requests []models.AssessRequest) models.Result[[]models.AssessResponse] {
	m.executeCalled = true

	if len(requests) > 0 {
		m.lastRequest = &requests[0]
	}

	if m.shouldFail {
		return models.Err[[]models.AssessResponse](fmt.Errorf("batch execution failed: %s", m.failureMessage))
	}

	// If we have predefined responses, use them
	if len(m.batchResponses) > 0 {
		return models.Ok(m.batchResponses)
	}

	// Otherwise, generate responses for each request
	responses := make([]models.AssessResponse, len(requests))
	for i, req := range requests {
		responses[i] = models.AssessResponse{
			ID:         uuid.New(),
			PluginName: m.name,
			Status:     "completed",
			StartTime:  time.Now().Add(-m.executionDuration),
			EndTime:    time.Now(),
			Findings:   m.findings,
			Metadata: map[string]interface{}{
				"test_execution": true,
				"batch_index":    i,
				"request_id":     req.ID.String(),
			},
		}
	}

	return models.Ok(responses)
}

// MockErrorPlugin always returns errors for testing error handling
type MockErrorPlugin struct {
	*MockPlugin
}

func NewMockErrorPlugin() *MockErrorPlugin {
	mock := NewMockPlugin()
	mock.shouldFail = true
	mock.failureMessage = "simulated error"
	return &MockErrorPlugin{MockPlugin: mock}
}

// MockSlowPlugin simulates slow execution for timeout testing
type MockSlowPlugin struct {
	*MockPlugin
}

func NewMockSlowPlugin(duration time.Duration) *MockSlowPlugin {
	mock := NewMockPlugin()
	mock.executionDuration = duration
	return &MockSlowPlugin{MockPlugin: mock}
}
