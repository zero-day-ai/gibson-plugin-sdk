package testing

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTestPlugin implements plugin.SecurityPlugin for testing
type MockTestPlugin struct {
	infoResult     models.Result[*plugin.PluginInfo]
	executeResult  models.Result[*plugin.AssessResponse]
	validateResult models.Result[*plugin.ValidationResult]
	healthResult   models.Result[*plugin.HealthStatus]

	executeCalls int
}

func NewMockTestPlugin() *MockTestPlugin {
	return &MockTestPlugin{
		infoResult: models.Ok(&plugin.PluginInfo{
			Name:    "test-plugin",
			Version: "1.0.0",
			Domain:  plugin.DomainInterface,
		}),
		executeResult: models.Ok(&plugin.AssessResponse{
			Success:   true,
			Completed: true,
			Findings:  []*plugin.Finding{},
		}),
		validateResult: models.Ok(&plugin.ValidationResult{
			Valid:   true,
			Message: "validation passed",
		}),
		healthResult: models.Ok(&plugin.HealthStatus{
			Status:  plugin.HealthStatusHealthy,
			Message: "plugin is healthy",
		}),
	}
}

func (m *MockTestPlugin) GetInfo(ctx context.Context) models.Result[*plugin.PluginInfo] {
	return m.infoResult
}

func (m *MockTestPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
	m.executeCalls++
	return m.executeResult
}

func (m *MockTestPlugin) Validate(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.ValidationResult] {
	return m.validateResult
}

func (m *MockTestPlugin) Health(ctx context.Context) models.Result[*plugin.HealthStatus] {
	return m.healthResult
}

func (m *MockTestPlugin) SetExecuteResult(result models.Result[*plugin.AssessResponse]) {
	m.executeResult = result
}

func (m *MockTestPlugin) SetHealthResult(result models.Result[*plugin.HealthStatus]) {
	m.healthResult = result
}

func TestTestResult(t *testing.T) {
	result := TestResult{
		Name:        "test_case",
		Passed:      true,
		Duration:    100 * time.Millisecond,
		Description: "Test description",
	}

	assert.Equal(t, "test_case", result.Name)
	assert.True(t, result.Passed)
	assert.Equal(t, 100*time.Millisecond, result.Duration)
	assert.Equal(t, "Test description", result.Description)
	assert.Empty(t, result.Error)
}

func TestPerformanceMetrics(t *testing.T) {
	metrics := PerformanceMetrics{
		ExecutionTime: 500 * time.Millisecond,
		MemoryUsage:   1024 * 1024, // 1MB
		CPUUsage:      25.5,
		ThroughputRPS: 100.0,
		LatencyP50:    10 * time.Millisecond,
		LatencyP95:    50 * time.Millisecond,
		LatencyP99:    100 * time.Millisecond,
		ErrorRate:     0.01, // 1%
	}

	assert.Equal(t, 500*time.Millisecond, metrics.ExecutionTime)
	assert.Equal(t, int64(1024*1024), metrics.MemoryUsage)
	assert.Equal(t, 25.5, metrics.CPUUsage)
	assert.Equal(t, 100.0, metrics.ThroughputRPS)
	assert.Equal(t, 0.01, metrics.ErrorRate)
}

func TestComplianceReport(t *testing.T) {
	now := time.Now()
	report := ComplianceReport{
		PluginName:    "test-plugin",
		PluginVersion: "1.0.0",
		TestedAt:      now,
		OverallPassed: true,
		TestResults: []TestResult{
			{
				Name:   "interface_compliance",
				Passed: true,
			},
		},
		Recommendations: []string{
			"Consider adding more error handling",
		},
	}

	assert.Equal(t, "test-plugin", report.PluginName)
	assert.Equal(t, "1.0.0", report.PluginVersion)
	assert.Equal(t, now, report.TestedAt)
	assert.True(t, report.OverallPassed)
	assert.Len(t, report.TestResults, 1)
	assert.Len(t, report.Recommendations, 1)
}

func TestNewPluginTestHarness(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	assert.NotNil(t, harness)
	assert.Equal(t, mockPlugin, harness.plugin)
	assert.Equal(t, 30*time.Second, harness.timeout)
	assert.Equal(t, 10, harness.maxConcurrent)
	assert.False(t, harness.strictMode)
	assert.NotNil(t, harness.testData)
}

func TestPluginTestHarness_WithTimeout(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	newTimeout := 60 * time.Second
	harness = harness.WithTimeout(newTimeout)

	assert.Equal(t, newTimeout, harness.timeout)
}

func TestPluginTestHarness_WithConcurrency(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	newConcurrency := 20
	harness = harness.WithConcurrency(newConcurrency)

	assert.Equal(t, newConcurrency, harness.maxConcurrent)
}

func TestPluginTestHarness_WithStrictMode(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	harness = harness.WithStrictMode(true)
	assert.True(t, harness.strictMode)

	harness = harness.WithStrictMode(false)
	assert.False(t, harness.strictMode)
}

func TestPluginTestHarness_WithTestData(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	customData := &TestDataSet{
		ValidTargets: []*plugin.Target{
			{
				ID:   "custom-target",
				Name: "Custom Target",
				Type: "api",
			},
		},
	}

	harness = harness.WithTestData(customData)
	assert.Equal(t, customData, harness.testData)
}

func TestPluginTestHarness_RunComplianceTests(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin).WithTimeout(5 * time.Second)

	ctx := context.Background()
	report, err := harness.RunComplianceTests(ctx)

	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "test-plugin", report.PluginName)
	assert.Equal(t, "1.0.0", report.PluginVersion)
	assert.NotZero(t, report.TestedAt)
	assert.NotEmpty(t, report.TestResults)

	// Check that all tests passed
	for _, result := range report.TestResults {
		if !result.Passed {
			t.Errorf("Test '%s' failed: %s", result.Name, result.Error)
		}
	}
}

func TestPluginTestHarness_RunComplianceTests_WithFailures(t *testing.T) {
	mockPlugin := NewMockTestPlugin()

	// Make the health check fail
	mockPlugin.SetHealthResult(models.Err[*plugin.HealthStatus](assert.AnError))

	harness := NewPluginTestHarness(mockPlugin).WithTimeout(5 * time.Second)

	ctx := context.Background()
	report, err := harness.RunComplianceTests(ctx)

	require.NoError(t, err)
	require.NotNil(t, report)

	// The overall result should be false due to health check failure
	assert.False(t, report.OverallPassed)

	// Find the failed health test
	var healthTestFound bool
	for _, result := range report.TestResults {
		if result.Name == "health_check" && !result.Passed {
			healthTestFound = true
			break
		}
	}
	assert.True(t, healthTestFound, "Health check test should have failed")
}

func TestPluginTestHarness_testPluginInfo(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testPluginInfo(ctx)

	assert.Equal(t, "plugin_info", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Plugin info retrieval")
}

func TestPluginTestHarness_testHealthCheck(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testHealthCheck(ctx)

	assert.Equal(t, "health_check", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Plugin health check")
}

func TestPluginTestHarness_testBasicExecution(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testBasicExecution(ctx)

	assert.Equal(t, "basic_execution", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Basic plugin execution")
	assert.Equal(t, 1, mockPlugin.executeCalls)
}

func TestPluginTestHarness_testInputValidation(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testInputValidation(ctx)

	assert.Equal(t, "input_validation", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Input validation")
}

func TestPluginTestHarness_testErrorHandling(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testErrorHandling(ctx)

	assert.Equal(t, "error_handling", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Error handling")
}

func TestPluginTestHarness_testPerformance(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testPerformance(ctx)

	assert.Equal(t, "performance", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Performance benchmarks")
}

func TestPluginTestHarness_testConcurrency(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testConcurrency(ctx)

	assert.Equal(t, "concurrency", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Concurrent execution")
}

func TestPluginTestHarness_testResourceManagement(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	result := harness.testResourceManagement(ctx)

	assert.Equal(t, "resource_management", result.Name)
	assert.True(t, result.Passed)
	assert.Empty(t, result.Error)
	assert.Contains(t, result.Description, "Resource management")
}

func TestPluginTestHarness_RunBenchmark(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	metrics, err := harness.RunBenchmark(ctx, 100, 10)

	require.NoError(t, err)
	require.NotNil(t, metrics)

	assert.True(t, metrics.ExecutionTime > 0)
	assert.True(t, metrics.ThroughputRPS > 0)
	assert.True(t, metrics.LatencyP50 >= 0)
	assert.True(t, metrics.LatencyP95 >= 0)
	assert.True(t, metrics.LatencyP99 >= 0)
	assert.True(t, metrics.ErrorRate >= 0)
}

func TestPluginTestHarness_RunLoadTest(t *testing.T) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)

	ctx := context.Background()
	results, err := harness.RunLoadTest(ctx, 50, 5, time.Second)

	require.NoError(t, err)
	require.NotNil(t, results)
	assert.Len(t, results, 50)

	// Check that all executions completed
	for i, result := range results {
		assert.True(t, result.Success, "Request %d should have succeeded", i)
	}
}

func TestGetDefaultTestData(t *testing.T) {
	data := GetDefaultTestData()

	require.NotNil(t, data)
	assert.NotEmpty(t, data.ValidTargets)
	assert.NotEmpty(t, data.InvalidTargets)
	assert.NotEmpty(t, data.TestConfigs)
	assert.NotEmpty(t, data.ExpectedErrors)

	// Verify valid targets have required fields
	for i, target := range data.ValidTargets {
		assert.NotEmpty(t, target.ID, "Valid target %d should have ID", i)
		assert.NotEmpty(t, target.Name, "Valid target %d should have Name", i)
		assert.NotEmpty(t, target.Type, "Valid target %d should have Type", i)
	}

	// Verify test configs have required fields
	for i, config := range data.TestConfigs {
		assert.NotEmpty(t, config.Domain, "Test config %d should have Domain", i)
	}
}

func TestCreateTestTargets(t *testing.T) {
	targets := CreateTestTargets()

	require.NotEmpty(t, targets)

	for i, target := range targets {
		assert.NotEmpty(t, target.ID, "Target %d should have ID", i)
		assert.NotEmpty(t, target.Name, "Target %d should have Name", i)
		assert.NotEmpty(t, target.Type, "Target %d should have Type", i)
	}
}

func TestCreateTestConfigs(t *testing.T) {
	configs := CreateTestConfigs()

	require.NotEmpty(t, configs)

	for i, config := range configs {
		assert.NotEmpty(t, config.Domain, "Config %d should have Domain", i)
		assert.True(t, config.MaxFindings >= 0, "Config %d should have non-negative MaxFindings", i)
		assert.True(t, config.TimeoutSeconds >= 0, "Config %d should have non-negative TimeoutSeconds", i)
	}
}

// Benchmark tests
func BenchmarkPluginTestHarness_testBasicExecution(b *testing.B) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		harness.testBasicExecution(ctx)
	}
}

func BenchmarkPluginTestHarness_RunBenchmark(b *testing.B) {
	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		harness.RunBenchmark(ctx, 10, 2)
	}
}

// Test helpers
func TestPluginTestHarness_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockPlugin := NewMockTestPlugin()
	harness := NewPluginTestHarness(mockPlugin).
		WithTimeout(10 * time.Second).
		WithConcurrency(5).
		WithStrictMode(true)

	ctx := context.Background()

	// Run compliance tests
	report, err := harness.RunComplianceTests(ctx)
	require.NoError(t, err)
	require.NotNil(t, report)

	// Run benchmark
	metrics, err := harness.RunBenchmark(ctx, 100, 10)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// Run load test
	results, err := harness.RunLoadTest(ctx, 50, 5, time.Second)
	require.NoError(t, err)
	require.NotNil(t, results)

	// Verify overall results
	assert.True(t, report.OverallPassed)
	assert.True(t, metrics.ThroughputRPS > 0)
	assert.Len(t, results, 50)
}
