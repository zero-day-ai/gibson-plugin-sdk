//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSDKIntegration_CompleteWorkflow tests the complete SDK workflow
func TestSDKIntegration_CompleteWorkflow(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create a test plugin
	testPlugin := NewIntegrationTestPlugin()

	// Step 2: Get plugin information
	t.Run("PluginInfo", func(t *testing.T) {
		infoResult := testPlugin.GetInfo(ctx)
		require.True(t, infoResult.IsOk(), "Should get plugin info successfully")

		info := infoResult.Unwrap()
		assert.Equal(t, "integration-test-plugin", info.Name)
		assert.Equal(t, "1.0.0", info.Version)
		assert.Equal(t, plugin.DomainInterface, info.Domain)
		assert.NotNil(t, info.Capabilities)
		assert.NotEmpty(t, info.SupportedPayloadTypes)

		// Validate plugin info structure
		validator := validation.NewValidator()
		validationResult := validator.ValidatePluginInfo(info)
		assert.False(t, validationResult.HasErrors(), "Plugin info should be valid")
	})

	// Step 3: Test health check
	t.Run("HealthCheck", func(t *testing.T) {
		healthResult := testPlugin.Health(ctx)
		require.True(t, healthResult.IsOk(), "Health check should succeed")

		health := healthResult.Unwrap()
		assert.Equal(t, plugin.HealthStatusHealthy, health.Status)
		assert.NotEmpty(t, health.Message)
		assert.False(t, health.Timestamp.IsZero())
	})

	// Step 4: Create and validate assessment request
	t.Run("AssessmentRequest", func(t *testing.T) {
		request := &plugin.AssessRequest{
			RequestID: "integration-test-request",
			Target: &plugin.Target{
				ID:       "integration-target",
				Name:     "Integration Test Target",
				Type:     "api",
				Endpoint: "https://api.example.com",
				Configuration: map[string]string{
					"timeout":    "30s",
					"auth_type":  "bearer",
					"rate_limit": "100",
				},
				Tags: []string{"integration", "test", "api"},
				Metadata: map[string]string{
					"environment": "test",
					"version":     "1.0",
				},
			},
			Config: &plugin.AssessmentConfig{
				Domain:              plugin.DomainInterface,
				PayloadTypes:        []plugin.PayloadType{plugin.PayloadTypeInput, plugin.PayloadTypeQuery},
				MaxFindings:         50,
				TimeoutSeconds:      60,
				EnableStreaming:     false,
				ConcurrentExecution: true,
				Options: map[string]interface{}{
					"aggressive_mode": false,
					"custom_payloads": []string{"test1", "test2"},
				},
			},
			Context: map[string]string{
				"user_id":    "integration-user",
				"session_id": "integration-session",
			},
		}

		// Validate request structure
		validator := validation.NewValidator().WithStrictMode(true)
		validationResult := validator.ValidateAssessRequest(request)
		assert.False(t, validationResult.HasErrors(), "Assessment request should be valid")

		// Test plugin validation
		pluginValidationResult := testPlugin.Validate(ctx, request)
		require.True(t, pluginValidationResult.IsOk(), "Plugin validation should succeed")

		validation := pluginValidationResult.Unwrap()
		assert.True(t, validation.Valid, "Request should be valid according to plugin")
	})

	// Step 5: Execute assessment
	t.Run("ExecuteAssessment", func(t *testing.T) {
		request := &plugin.AssessRequest{
			RequestID: "integration-execute-request",
			Target: &plugin.Target{
				ID:   "execute-target",
				Name: "Execute Test Target",
				Type: "api",
			},
			Config: &plugin.AssessmentConfig{
				Domain:         plugin.DomainInterface,
				PayloadTypes:   []plugin.PayloadType{plugin.PayloadTypeInput},
				MaxFindings:    10,
				TimeoutSeconds: 30,
			},
		}

		executeResult := testPlugin.Execute(ctx, request)
		require.True(t, executeResult.IsOk(), "Execution should succeed")

		response := executeResult.Unwrap()
		assert.True(t, response.Success, "Assessment should be successful")
		assert.True(t, response.Completed, "Assessment should be completed")
		assert.Equal(t, "integration-execute-request", response.RequestID)
		assert.NotEmpty(t, response.Findings, "Should have findings")
		assert.NotNil(t, response.ResourceUsage, "Should have resource usage data")
		assert.True(t, response.Duration > 0, "Should have execution duration")

		// Validate findings
		for i, finding := range response.Findings {
			assert.NotEmpty(t, finding.ID, "Finding %d should have ID", i)
			assert.NotEmpty(t, finding.Title, "Finding %d should have title", i)
			assert.NotEmpty(t, finding.Description, "Finding %d should have description", i)
			assert.True(t, plugin.IsValidSeverity(finding.Severity), "Finding %d should have valid severity", i)
			assert.True(t, plugin.IsValidDomain(finding.Domain), "Finding %d should have valid domain", i)
			assert.False(t, finding.DiscoveredAt.IsZero(), "Finding %d should have discovery time", i)

			// Validate finding structure
			validator := validation.NewValidator()
			validationResult := validator.ValidateFinding(finding)
			assert.False(t, validationResult.HasErrors(), "Finding %d should be valid", i)
		}
	})

	// Step 6: Test different target types
	targetTypes := []struct {
		name           string
		targetType     string
		expectedDomain plugin.SecurityDomain
	}{
		{"API Target", "api", plugin.DomainInterface},
		{"Website Target", "website", plugin.DomainInterface},
		{"Model Target", "model", plugin.DomainModel},
	}

	for _, tt := range targetTypes {
		t.Run(tt.name, func(t *testing.T) {
			request := &plugin.AssessRequest{
				RequestID: "target-type-test-" + tt.targetType,
				Target: &plugin.Target{
					ID:   "target-" + tt.targetType,
					Name: tt.name,
					Type: tt.targetType,
				},
				Config: &plugin.AssessmentConfig{
					Domain: plugin.DomainInterface,
				},
			}

			result := testPlugin.Execute(ctx, request)
			require.True(t, result.IsOk(), "Execution should succeed for %s", tt.name)

			response := result.Unwrap()
			assert.True(t, response.Success, "Assessment should succeed for %s", tt.name)

			if len(response.Findings) > 0 {
				finding := response.Findings[0]
				assert.Equal(t, tt.expectedDomain, finding.Domain, "Finding domain should match expected for %s", tt.name)
			}
		})
	}

	// Step 7: Test error handling
	t.Run("ErrorHandling", func(t *testing.T) {
		// Test with invalid request
		invalidRequest := &plugin.AssessRequest{
			RequestID: "", // Invalid empty request ID
			Target:    nil, // Invalid nil target
		}

		validationResult := testPlugin.Validate(ctx, invalidRequest)
		require.True(t, validationResult.IsOk(), "Validation should return result")

		validation := validationResult.Unwrap()
		assert.False(t, validation.Valid, "Invalid request should fail validation")
		assert.NotEmpty(t, validation.Message, "Should have validation error message")

		// Test execution with invalid request
		executeResult := testPlugin.Execute(ctx, invalidRequest)
		require.True(t, executeResult.IsOk(), "Should return result even for invalid request")

		response := executeResult.Unwrap()
		assert.False(t, response.Success, "Execution should fail for invalid request")
		assert.NotEmpty(t, response.Error, "Should have error message")
	})

	// Step 8: Test concurrent execution
	t.Run("ConcurrentExecution", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping concurrent execution test in short mode")
		}

		numGoroutines := 5
		numRequestsPerGoroutine := 3
		resultChan := make(chan bool, numGoroutines*numRequestsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				for j := 0; j < numRequestsPerGoroutine; j++ {
					request := &plugin.AssessRequest{
						RequestID: "concurrent-" + string(rune(goroutineID)) + "-" + string(rune(j)),
						Target: &plugin.Target{
							ID:   "concurrent-target-" + string(rune(goroutineID)),
							Name: "Concurrent Target",
							Type: "api",
						},
						Config: &plugin.AssessmentConfig{
							Domain: plugin.DomainInterface,
						},
					}

					result := testPlugin.Execute(ctx, request)
					success := result.IsOk() && result.Unwrap().Success
					resultChan <- success
				}
			}(i)
		}

		// Collect results
		successCount := 0
		totalRequests := numGoroutines * numRequestsPerGoroutine
		for i := 0; i < totalRequests; i++ {
			if <-resultChan {
				successCount++
			}
		}

		assert.Equal(t, totalRequests, successCount, "All concurrent requests should succeed")
	})
}

func TestSDKIntegration_ResultPattern(t *testing.T) {
	t.Run("ResultOk", func(t *testing.T) {
		result := models.Ok("test value")
		assert.True(t, result.IsOk())
		assert.False(t, result.IsErr())
		assert.Equal(t, "test value", result.Unwrap())
		assert.Nil(t, result.Error())
	})

	t.Run("ResultErr", func(t *testing.T) {
		testErr := assert.AnError
		result := models.Err[string](testErr)
		assert.False(t, result.IsOk())
		assert.True(t, result.IsErr())
		assert.Equal(t, testErr, result.Error())
		assert.Equal(t, "", result.UnwrapOr("default"))
	})

	t.Run("ResultChaining", func(t *testing.T) {
		// Test chaining operations with Result pattern
		getValue := func() models.Result[int] {
			return models.Ok(42)
		}

		processValue := func(value int) models.Result[string] {
			if value > 0 {
				return models.Ok("positive")
			}
			return models.Err[string](assert.AnError)
		}

		result := getValue()
		require.True(t, result.IsOk())

		processed := processValue(result.Unwrap())
		require.True(t, processed.IsOk())
		assert.Equal(t, "positive", processed.Unwrap())
	})
}

func TestSDKIntegration_ValidationWorkflow(t *testing.T) {
	validator := validation.NewValidator().WithStrictMode(true)

	t.Run("PluginInfoValidation", func(t *testing.T) {
		info := &plugin.PluginInfo{
			Name:        "validation-test-plugin",
			Version:     "1.0.0",
			Description: "Plugin for validation testing",
			Author:      "Test Team",
			Domain:      plugin.DomainInterface,
			SupportedPayloadTypes: []plugin.PayloadType{
				plugin.PayloadTypeInput,
				plugin.PayloadTypeQuery,
			},
			Capabilities: &plugin.PluginCapabilities{
				MaxConcurrentRequests: 10,
				TimeoutSeconds:        30,
			},
		}

		result := validator.ValidatePluginInfo(info)
		assert.False(t, result.HasErrors(), "Valid plugin info should pass validation")
		assert.True(t, result.Valid, "Validation result should be valid")
	})

	t.Run("PayloadValidation", func(t *testing.T) {
		testCases := []struct {
			name      string
			payload   string
			expectErr bool
		}{
			{"Safe payload", "normal input text", false},
			{"SQL injection", "'; DROP TABLE users; --", true},
			{"XSS attack", "<script>alert('xss')</script>", true},
			{"Command injection", "; rm -rf /", true},
			{"Large payload", string(make([]byte, 50000)), false},
			{"Oversized payload", string(make([]byte, 200000)), true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := validator.ValidatePayload(tc.payload)
				if tc.expectErr {
					assert.True(t, result.HasErrors(), "Should detect security issue in payload")
				} else {
					assert.False(t, result.HasErrors(), "Safe payload should pass validation")
				}
			})
		}
	})
}

func TestSDKIntegration_PerformanceBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	plugin := NewIntegrationTestPlugin()
	ctx := context.Background()

	request := &plugin.AssessRequest{
		RequestID: "performance-test",
		Target: &plugin.Target{
			ID:   "performance-target",
			Name: "Performance Test Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	// Warm up
	for i := 0; i < 5; i++ {
		plugin.Execute(ctx, request)
	}

	// Measure performance
	numRequests := 100
	startTime := time.Now()

	for i := 0; i < numRequests; i++ {
		result := plugin.Execute(ctx, request)
		require.True(t, result.IsOk(), "Request %d should succeed", i)
	}

	totalTime := time.Since(startTime)
	averageTime := totalTime / time.Duration(numRequests)
	requestsPerSecond := float64(numRequests) / totalTime.Seconds()

	t.Logf("Performance baseline:")
	t.Logf("- Total time: %v", totalTime)
	t.Logf("- Average time per request: %v", averageTime)
	t.Logf("- Requests per second: %.2f", requestsPerSecond)

	// Performance assertions
	assert.True(t, averageTime < 50*time.Millisecond, "Average request time should be under 50ms")
	assert.True(t, requestsPerSecond > 20, "Should handle at least 20 requests per second")
}

// Benchmark integration tests
func BenchmarkSDKIntegration_PluginExecution(b *testing.B) {
	plugin := NewIntegrationTestPlugin()
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

func BenchmarkSDKIntegration_Validation(b *testing.B) {
	validator := validation.NewValidator()
	request := &plugin.AssessRequest{
		RequestID: "benchmark-validation",
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
		result := validator.ValidateAssessRequest(request)
		if result.HasErrors() {
			b.Fatal("Validation failed")
		}
	}
}