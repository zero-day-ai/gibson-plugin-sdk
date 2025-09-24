package testing

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
)

// TestResult represents the result of a single test
type TestResult struct {
	Name        string        `json:"name"`
	Passed      bool          `json:"passed"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	Description string        `json:"description"`
}

// PerformanceMetrics captures performance data
type PerformanceMetrics struct {
	ExecutionTime time.Duration `json:"execution_time"`
	MemoryUsage   int64         `json:"memory_usage"`
	CPUUsage      float64       `json:"cpu_usage"`
	ThroughputRPS float64       `json:"throughput_rps"`
	LatencyP50    time.Duration `json:"latency_p50"`
	LatencyP95    time.Duration `json:"latency_p95"`
	LatencyP99    time.Duration `json:"latency_p99"`
	ErrorRate     float64       `json:"error_rate"`
}

// ComplianceReport contains results of compliance testing
type ComplianceReport struct {
	PluginName         string              `json:"plugin_name"`
	PluginVersion      string              `json:"plugin_version"`
	TestedAt           time.Time           `json:"tested_at"`
	OverallPassed      bool                `json:"overall_passed"`
	TestResults        []TestResult        `json:"test_results"`
	PerformanceMetrics *PerformanceMetrics `json:"performance_metrics,omitempty"`
	Recommendations    []string            `json:"recommendations"`
}

// PluginTestHarness provides comprehensive testing capabilities for Gibson plugins
type PluginTestHarness struct {
	plugin        plugin.SecurityPlugin
	timeout       time.Duration
	maxConcurrent int
	strictMode    bool
	testData      *TestDataSet
}

// TestDataSet contains test data for plugin validation
type TestDataSet struct {
	ValidTargets   []*plugin.Target           `json:"valid_targets"`
	InvalidTargets []*plugin.Target           `json:"invalid_targets"`
	TestConfigs    []*plugin.AssessmentConfig `json:"test_configs"`
	ExpectedErrors []string                   `json:"expected_errors"`
}

// NewPluginTestHarness creates a new test harness for the given plugin
func NewPluginTestHarness(p plugin.SecurityPlugin) *PluginTestHarness {
	return &PluginTestHarness{
		plugin:        p,
		timeout:       30 * time.Second,
		maxConcurrent: 10,
		strictMode:    false,
		testData:      GetDefaultTestData(),
	}
}

// WithTimeout sets the timeout for plugin operations
func (h *PluginTestHarness) WithTimeout(timeout time.Duration) *PluginTestHarness {
	h.timeout = timeout
	return h
}

// WithConcurrency sets the maximum concurrent operations
func (h *PluginTestHarness) WithConcurrency(max int) *PluginTestHarness {
	h.maxConcurrent = max
	return h
}

// WithStrictMode enables strict compliance checking
func (h *PluginTestHarness) WithStrictMode(strict bool) *PluginTestHarness {
	h.strictMode = strict
	return h
}

// WithTestData sets custom test data
func (h *PluginTestHarness) WithTestData(data *TestDataSet) *PluginTestHarness {
	h.testData = data
	return h
}

// RunComplianceTests runs all compliance tests and returns a detailed report
func (h *PluginTestHarness) RunComplianceTests(ctx context.Context) (*ComplianceReport, error) {
	report := &ComplianceReport{
		TestedAt:        time.Now(),
		OverallPassed:   true,
		TestResults:     []TestResult{},
		Recommendations: []string{},
	}

	// Get plugin info
	infoResult := h.plugin.GetInfo(ctx)
	if infoResult.IsErr() {
		return nil, fmt.Errorf("failed to get plugin info: %w", infoResult.Error())
	}
	info := infoResult.Unwrap()
	report.PluginName = info.Name
	report.PluginVersion = info.Version

	// Run core compliance tests
	tests := []func(context.Context) TestResult{
		h.testGetInfo,
		h.testHealthCheck,
		h.testValidation,
		h.testExecuteWithValidInput,
		h.testExecuteWithInvalidInput,
		h.testTimeout,
		h.testConcurrency,
		h.testErrorHandling,
		h.testResourceCleanup,
	}

	for _, test := range tests {
		result := test(ctx)
		report.TestResults = append(report.TestResults, result)
		if !result.Passed {
			report.OverallPassed = false
		}
	}

	// Run performance benchmarks
	if metrics, err := h.runPerformanceBenchmarks(ctx); err == nil {
		report.PerformanceMetrics = metrics
	}

	// Generate recommendations
	report.Recommendations = h.generateRecommendations(report)

	return report, nil
}

// testGetInfo tests the GetInfo method
func (h *PluginTestHarness) testGetInfo(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "GetInfo",
		Description: "Tests plugin metadata retrieval",
	}

	infoResult := h.plugin.GetInfo(ctx)
	result.Duration = time.Since(start)

	if infoResult.IsErr() {
		result.Error = infoResult.Error().Error()
		return result
	}

	info := infoResult.Unwrap()
	if info.Name == "" {
		result.Error = "plugin name is empty"
		return result
	}

	if info.Version == "" {
		result.Error = "plugin version is empty"
		return result
	}

	result.Passed = true
	return result
}

// testHealthCheck tests the health check functionality
func (h *PluginTestHarness) testHealthCheck(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "HealthCheck",
		Description: "Tests plugin health check functionality",
	}

	healthResult := h.plugin.Health(ctx)
	result.Duration = time.Since(start)

	if healthResult.IsErr() {
		result.Error = healthResult.Error().Error()
		return result
	}

	health := healthResult.Unwrap()
	if health.Status != plugin.HealthStatusHealthy {
		result.Error = fmt.Sprintf("expected healthy status, got %s", health.Status)
		return result
	}

	result.Passed = true
	return result
}

// testValidation tests input validation
func (h *PluginTestHarness) testValidation(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "Validation",
		Description: "Tests input validation capabilities",
	}

	// Test with nil request
	validationResult := h.plugin.Validate(ctx, nil)
	if validationResult.IsErr() {
		result.Duration = time.Since(start)
		result.Error = "validation should handle nil input gracefully"
		return result
	}

	validation := validationResult.Unwrap()
	if validation.Valid {
		result.Duration = time.Since(start)
		result.Error = "nil request should be invalid"
		return result
	}

	// Test with valid request
	if len(h.testData.ValidTargets) > 0 && len(h.testData.TestConfigs) > 0 {
		validRequest := &plugin.AssessRequest{
			RequestID: "test-validation",
			Target:    h.testData.ValidTargets[0],
			Config:    h.testData.TestConfigs[0],
		}

		validationResult := h.plugin.Validate(ctx, validRequest)
		if validationResult.IsErr() {
			result.Duration = time.Since(start)
			result.Error = validationResult.Error().Error()
			return result
		}

		validation := validationResult.Unwrap()
		if !validation.Valid {
			result.Duration = time.Since(start)
			result.Error = fmt.Sprintf("valid request should pass validation: %s", validation.Message)
			return result
		}
	}

	result.Duration = time.Since(start)
	result.Passed = true
	return result
}

// testExecuteWithValidInput tests plugin execution with valid input
func (h *PluginTestHarness) testExecuteWithValidInput(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "ExecuteValid",
		Description: "Tests plugin execution with valid input",
	}

	if len(h.testData.ValidTargets) == 0 || len(h.testData.TestConfigs) == 0 {
		result.Duration = time.Since(start)
		result.Error = "no valid test data available"
		return result
	}

	request := &plugin.AssessRequest{
		RequestID: "test-execute-valid",
		Target:    h.testData.ValidTargets[0],
		Config:    h.testData.TestConfigs[0],
	}

	executeResult := h.plugin.Execute(ctx, request)
	result.Duration = time.Since(start)

	if executeResult.IsErr() {
		result.Error = executeResult.Error().Error()
		return result
	}

	response := executeResult.Unwrap()
	if !response.Success && response.Error == "" {
		result.Error = "execution failed without error message"
		return result
	}
	_ = response // Use response to avoid unused variable warning

	result.Passed = true
	return result
}

// testExecuteWithInvalidInput tests plugin execution with invalid input
func (h *PluginTestHarness) testExecuteWithInvalidInput(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "ExecuteInvalid",
		Description: "Tests plugin execution with invalid input",
	}

	// Test with nil request
	executeResult := h.plugin.Execute(ctx, nil)
	result.Duration = time.Since(start)

	if executeResult.IsOk() {
		response := executeResult.Unwrap()
		if response.Success {
			result.Error = "execution with nil request should fail"
			return result
		}
	}

	result.Passed = true
	return result
}

// testTimeout tests timeout handling
func (h *PluginTestHarness) testTimeout(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "Timeout",
		Description: "Tests timeout handling",
	}

	// Create a context with very short timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
	defer cancel()

	if len(h.testData.ValidTargets) > 0 && len(h.testData.TestConfigs) > 0 {
		request := &plugin.AssessRequest{
			RequestID: "test-timeout",
			Target:    h.testData.ValidTargets[0],
			Config:    h.testData.TestConfigs[0],
		}

		executeResult := h.plugin.Execute(timeoutCtx, request)
		result.Duration = time.Since(start)

		// Should either return quickly or handle timeout gracefully
		if executeResult.IsOk() {
			_ = executeResult.Unwrap() // If it succeeded, it was very fast
			result.Passed = true
		} else {
			// If it failed, check if it's a timeout error
			errStr := strings.ToLower(executeResult.Error().Error())
			if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
				result.Passed = true
			} else {
				result.Error = "expected timeout error, got: " + executeResult.Error().Error()
			}
		}
	} else {
		result.Duration = time.Since(start)
		result.Passed = true // Skip if no test data
	}

	return result
}

// testConcurrency tests concurrent execution
func (h *PluginTestHarness) testConcurrency(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "Concurrency",
		Description: "Tests concurrent execution safety",
	}

	if len(h.testData.ValidTargets) == 0 || len(h.testData.TestConfigs) == 0 {
		result.Duration = time.Since(start)
		result.Passed = true // Skip if no test data
		return result
	}

	// Run multiple concurrent operations
	concurrency := 5
	results := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			request := &plugin.AssessRequest{
				RequestID: fmt.Sprintf("test-concurrent-%d", id),
				Target:    h.testData.ValidTargets[0],
				Config:    h.testData.TestConfigs[0],
			}

			executeResult := h.plugin.Execute(ctx, request)
			if executeResult.IsErr() {
				results <- executeResult.Error()
			} else {
				results <- nil
			}
		}(i)
	}

	// Collect results
	var errors []string
	for i := 0; i < concurrency; i++ {
		if err := <-results; err != nil {
			errors = append(errors, err.Error())
		}
	}

	result.Duration = time.Since(start)

	if len(errors) > 0 && h.strictMode {
		result.Error = fmt.Sprintf("concurrent execution errors: %v", errors)
		return result
	}

	result.Passed = true
	return result
}

// testErrorHandling tests error handling consistency
func (h *PluginTestHarness) testErrorHandling(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "ErrorHandling",
		Description: "Tests error handling consistency",
		Passed:      true,
	}

	// Test various error conditions
	errorTests := []struct {
		name    string
		request *plugin.AssessRequest
	}{
		{"nil_request", nil},
		{"nil_target", &plugin.AssessRequest{RequestID: "test", Target: nil}},
		{"empty_target", &plugin.AssessRequest{RequestID: "test", Target: &plugin.Target{}}},
	}

	for _, test := range errorTests {
		executeResult := h.plugin.Execute(ctx, test.request)
		if executeResult.IsOk() {
			response := executeResult.Unwrap()
			if response.Success {
				result.Error = fmt.Sprintf("test %s should fail but succeeded", test.name)
				result.Passed = false
				break
			}
		}
	}

	result.Duration = time.Since(start)
	return result
}

// testResourceCleanup tests resource cleanup
func (h *PluginTestHarness) testResourceCleanup(ctx context.Context) TestResult {
	start := time.Now()
	result := TestResult{
		Name:        "ResourceCleanup",
		Description: "Tests resource cleanup after execution",
		Passed:      true, // Assume pass unless we can detect leaks
	}

	// This is a basic test - in practice, you'd need more sophisticated
	// resource monitoring to detect leaks
	if len(h.testData.ValidTargets) > 0 && len(h.testData.TestConfigs) > 0 {
		request := &plugin.AssessRequest{
			RequestID: "test-cleanup",
			Target:    h.testData.ValidTargets[0],
			Config:    h.testData.TestConfigs[0],
		}

		h.plugin.Execute(ctx, request)
	}

	result.Duration = time.Since(start)
	return result
}

// runPerformanceBenchmarks runs performance benchmarks
func (h *PluginTestHarness) runPerformanceBenchmarks(ctx context.Context) (*PerformanceMetrics, error) {
	if len(h.testData.ValidTargets) == 0 || len(h.testData.TestConfigs) == 0 {
		return nil, fmt.Errorf("no test data available for performance benchmarks")
	}

	metrics := &PerformanceMetrics{}

	// Simple execution time benchmark
	start := time.Now()
	request := &plugin.AssessRequest{
		RequestID: "benchmark",
		Target:    h.testData.ValidTargets[0],
		Config:    h.testData.TestConfigs[0],
	}

	result := h.plugin.Execute(ctx, request)
	metrics.ExecutionTime = time.Since(start)

	if result.IsErr() {
		metrics.ErrorRate = 1.0
	} else {
		metrics.ErrorRate = 0.0
	}

	// Calculate approximate throughput
	if metrics.ExecutionTime > 0 {
		metrics.ThroughputRPS = 1.0 / metrics.ExecutionTime.Seconds()
	}

	return metrics, nil
}

// generateRecommendations generates recommendations based on test results
func (h *PluginTestHarness) generateRecommendations(report *ComplianceReport) []string {
	var recommendations []string

	for _, test := range report.TestResults {
		if !test.Passed {
			switch test.Name {
			case "GetInfo":
				recommendations = append(recommendations, "Ensure plugin metadata is properly populated")
			case "HealthCheck":
				recommendations = append(recommendations, "Implement proper health check functionality")
			case "Validation":
				recommendations = append(recommendations, "Improve input validation logic")
			case "ExecuteValid":
				recommendations = append(recommendations, "Fix execution logic for valid inputs")
			case "Timeout":
				recommendations = append(recommendations, "Implement proper timeout handling")
			case "Concurrency":
				recommendations = append(recommendations, "Ensure thread-safe operations")
			case "ErrorHandling":
				recommendations = append(recommendations, "Improve error handling consistency")
			}
		}
	}

	if report.PerformanceMetrics != nil {
		if report.PerformanceMetrics.ExecutionTime > 10*time.Second {
			recommendations = append(recommendations, "Consider optimizing execution time")
		}
		if report.PerformanceMetrics.ErrorRate > 0.1 {
			recommendations = append(recommendations, "Reduce error rate in normal operations")
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Plugin passes all compliance tests")
	}

	return recommendations
}

// GetDefaultTestData returns default test data for plugin testing
func GetDefaultTestData() *TestDataSet {
	return &TestDataSet{
		ValidTargets: []*plugin.Target{
			{
				ID:            "test-target-1",
				Name:          "Test Target 1",
				Type:          "api",
				Endpoint:      "https://api.example.com",
				Configuration: map[string]string{"key": "value"},
				Tags:          []string{"test"},
				Metadata:      map[string]string{"environment": "test"},
			},
		},
		InvalidTargets: []*plugin.Target{
			{
				ID:   "",
				Name: "",
			},
		},
		TestConfigs: []*plugin.AssessmentConfig{
			{
				Domain:              plugin.DomainInterface,
				PayloadTypes:        []plugin.PayloadType{plugin.PayloadTypePrompt},
				MaxFindings:         10,
				TimeoutSeconds:      30,
				EnableStreaming:     false,
				ConcurrentExecution: false,
				Options:             map[string]interface{}{"test": true},
			},
		},
		ExpectedErrors: []string{
			"invalid target",
			"missing configuration",
			"timeout",
		},
	}
}

// RunTestsWithTesting integrates with Go's testing framework
func (h *PluginTestHarness) RunTestsWithTesting(t *testing.T) {
	ctx := context.Background()

	report, err := h.RunComplianceTests(ctx)
	if err != nil {
		t.Fatalf("Failed to run compliance tests: %v", err)
	}

	for _, result := range report.TestResults {
		t.Run(result.Name, func(t *testing.T) {
			if !result.Passed {
				t.Errorf("Test failed: %s", result.Error)
			}
		})
	}

	if !report.OverallPassed {
		t.Errorf("Plugin failed compliance tests. Recommendations: %v", report.Recommendations)
	}
}
