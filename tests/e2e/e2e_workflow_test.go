//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/zero-day-ai/gibson-sdk/pkg/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// E2EWorkflowManager manages multiple plugins in realistic scenarios
type E2EWorkflowManager struct {
	plugins     map[string]*E2ETestPlugin
	validator   *validation.Validator
	metrics     *WorkflowMetrics
	mu          sync.RWMutex
}

type WorkflowMetrics struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	TotalFindings      int64         `json:"total_findings"`
	AverageLatency     time.Duration `json:"average_latency"`
	MaxLatency         time.Duration `json:"max_latency"`
	MinLatency         time.Duration `json:"min_latency"`
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	StartTime          time.Time     `json:"start_time"`
	EndTime            time.Time     `json:"end_time"`
}

func NewE2EWorkflowManager() *E2EWorkflowManager {
	return &E2EWorkflowManager{
		plugins:   make(map[string]*E2ETestPlugin),
		validator: validation.NewValidator().WithStrictMode(false),
		metrics: &WorkflowMetrics{
			MinLatency: time.Hour, // Initialize to high value
		},
	}
}

func (wm *E2EWorkflowManager) RegisterPlugin(name string, domain plugin.SecurityDomain) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.plugins[name] = NewE2ETestPlugin(name, domain)
}

func (wm *E2EWorkflowManager) ExecuteWorkflow(ctx context.Context, targets []*plugin.Target) (*WorkflowMetrics, error) {
	wm.metrics.StartTime = time.Now()
	defer func() {
		wm.metrics.EndTime = time.Now()
		wm.metrics.TotalExecutionTime = wm.metrics.EndTime.Sub(wm.metrics.StartTime)
	}()

	var wg sync.WaitGroup
	results := make(chan workflowResult, len(wm.plugins)*len(targets))

	// Execute each plugin against each target
	for pluginName, plugin := range wm.plugins {
		for _, target := range targets {
			wg.Add(1)
			go func(pName string, p *E2ETestPlugin, t *plugin.Target) {
				defer wg.Done()

				requestID := fmt.Sprintf("%s-%s-%d", pName, t.ID, time.Now().UnixNano())
				request := &plugin.AssessRequest{
					RequestID: requestID,
					Target:    t,
					Config: &plugin.AssessmentConfig{
						Domain:         p.GetDomain(),
						MaxFindings:    50,
						TimeoutSeconds: 30,
					},
				}

				startTime := time.Now()
				result := p.Execute(ctx, request)
				latency := time.Since(startTime)

				results <- workflowResult{
					PluginName: pName,
					TargetID:   t.ID,
					Success:    result.IsOk() && result.Unwrap().Success,
					Latency:    latency,
					Findings:   len(result.UnwrapOr(&plugin.AssessResponse{}).Findings),
					Error:      result.Error(),
				}
			}(pluginName, plugin, target)
		}
	}

	wg.Wait()
	close(results)

	// Collect and aggregate results
	var totalLatency time.Duration
	for result := range results {
		wm.updateMetrics(result)
		totalLatency += result.Latency
	}

	if wm.metrics.TotalRequests > 0 {
		wm.metrics.AverageLatency = totalLatency / time.Duration(wm.metrics.TotalRequests)
	}

	return wm.metrics, nil
}

type workflowResult struct {
	PluginName string
	TargetID   string
	Success    bool
	Latency    time.Duration
	Findings   int
	Error      error
}

func (wm *E2EWorkflowManager) updateMetrics(result workflowResult) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	wm.metrics.TotalRequests++
	wm.metrics.TotalFindings += int64(result.Findings)

	if result.Success {
		wm.metrics.SuccessfulRequests++
	} else {
		wm.metrics.FailedRequests++
	}

	if result.Latency > wm.metrics.MaxLatency {
		wm.metrics.MaxLatency = result.Latency
	}

	if result.Latency < wm.metrics.MinLatency {
		wm.metrics.MinLatency = result.Latency
	}
}

func (wm *E2EWorkflowManager) GetMetrics() *WorkflowMetrics {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.metrics
}

// TestE2E_CompleteSecurityWorkflow tests a complete security assessment workflow
func TestE2E_CompleteSecurityWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E complete workflow test in short mode")
	}

	ctx := context.Background()
	manager := NewE2EWorkflowManager()

	// Register plugins for all security domains
	domains := map[string]plugin.SecurityDomain{
		"ai-model-scanner":       plugin.DomainModel,
		"data-privacy-scanner":   plugin.DomainData,
		"interface-vuln-scanner": plugin.DomainInterface,
		"infra-security-scanner": plugin.DomainInfrastructure,
		"output-safety-scanner":  plugin.DomainOutput,
		"process-audit-scanner":  plugin.DomainProcess,
	}

	for name, domain := range domains {
		manager.RegisterPlugin(name, domain)
	}

	// Create realistic test targets
	targets := []*plugin.Target{
		{
			ID:       "prod-api-v1",
			Name:     "Production API v1",
			Type:     "api",
			Endpoint: "https://api.example.com/v1",
			Configuration: map[string]string{
				"rate_limit":     "1000",
				"auth_required":  "true",
				"version":        "1.2.3",
			},
			Tags: []string{"production", "api", "v1"},
		},
		{
			ID:   "ml-chatbot-model",
			Name: "ML Chatbot Model",
			Type: "model",
			Configuration: map[string]string{
				"model_type":    "transformer",
				"model_version": "2.1",
				"context_size":  "4096",
			},
			Tags: []string{"ml", "chatbot", "production"},
		},
		{
			ID:       "customer-portal",
			Name:     "Customer Portal Website",
			Type:     "website",
			Endpoint: "https://portal.example.com",
			Configuration: map[string]string{
				"framework": "react",
				"version":   "18.2.0",
			},
			Tags: []string{"portal", "customer", "frontend"},
		},
		{
			ID:   "data-warehouse",
			Name: "Data Warehouse System",
			Type: "system",
			Configuration: map[string]string{
				"db_type":     "postgresql",
				"db_version":  "14.5",
				"encryption":  "enabled",
			},
			Tags: []string{"data", "warehouse", "backend"},
		},
	}

	t.Run("ExecuteCompleteWorkflow", func(t *testing.T) {
		metrics, err := manager.ExecuteWorkflow(ctx, targets)
		require.NoError(t, err)
		require.NotNil(t, metrics)

		t.Logf("Workflow Results:")
		t.Logf("- Total requests: %d", metrics.TotalRequests)
		t.Logf("- Successful requests: %d", metrics.SuccessfulRequests)
		t.Logf("- Failed requests: %d", metrics.FailedRequests)
		t.Logf("- Total findings: %d", metrics.TotalFindings)
		t.Logf("- Success rate: %.2f%%", float64(metrics.SuccessfulRequests)/float64(metrics.TotalRequests)*100)
		t.Logf("- Average latency: %v", metrics.AverageLatency)
		t.Logf("- Max latency: %v", metrics.MaxLatency)
		t.Logf("- Min latency: %v", metrics.MinLatency)
		t.Logf("- Total execution time: %v", metrics.TotalExecutionTime)

		// Assertions
		expectedRequests := int64(len(domains) * len(targets))
		assert.Equal(t, expectedRequests, metrics.TotalRequests, "Should execute all plugin-target combinations")
		assert.True(t, metrics.SuccessfulRequests >= int64(float64(expectedRequests)*0.95), "Success rate should be at least 95%")
		assert.True(t, metrics.TotalFindings > 0, "Should generate findings")
		assert.True(t, metrics.AverageLatency < 100*time.Millisecond, "Average latency should be reasonable")
		assert.True(t, metrics.TotalExecutionTime > 0, "Should have measurable execution time")
	})
}

// TestE2E_ScalabilityStressTest tests SDK scalability under stress
func TestE2E_ScalabilityStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E scalability stress test in short mode")
	}

	ctx := context.Background()

	testCases := []struct {
		name        string
		numPlugins  int
		numTargets  int
		concurrency int
		duration    time.Duration
	}{
		{
			name:        "Small Scale",
			numPlugins:  3,
			numTargets:  5,
			concurrency: 10,
			duration:    10 * time.Second,
		},
		{
			name:        "Medium Scale",
			numPlugins:  6,
			numTargets:  10,
			concurrency: 20,
			duration:    15 * time.Second,
		},
		{
			name:        "Large Scale",
			numPlugins:  10,
			numTargets:  20,
			concurrency: 50,
			duration:    20 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create plugins
			plugins := make([]*E2ETestPlugin, tc.numPlugins)
			domains := []plugin.SecurityDomain{
				plugin.DomainModel, plugin.DomainData, plugin.DomainInterface,
				plugin.DomainInfrastructure, plugin.DomainOutput, plugin.DomainProcess,
			}

			for i := 0; i < tc.numPlugins; i++ {
				domain := domains[i%len(domains)]
				plugins[i] = NewE2ETestPlugin(fmt.Sprintf("stress-plugin-%d", i), domain)
				plugins[i].SetSimulatedLatency(5 * time.Millisecond) // Consistent latency
			}

			// Create targets
			targets := make([]*plugin.Target, tc.numTargets)
			targetTypes := []string{"api", "model", "website", "system"}

			for i := 0; i < tc.numTargets; i++ {
				targets[i] = &plugin.Target{
					ID:   fmt.Sprintf("stress-target-%d", i),
					Name: fmt.Sprintf("Stress Target %d", i),
					Type: targetTypes[i%len(targetTypes)],
				}
			}

			// Stress test execution
			startTime := time.Now()
			semaphore := make(chan struct{}, tc.concurrency)
			results := make(chan bool, tc.numPlugins*tc.numTargets*10) // Buffer for multiple iterations

			var wg sync.WaitGroup
			requestCount := 0

			// Run for specified duration
			for time.Since(startTime) < tc.duration {
				for _, plugin := range plugins {
					for _, target := range targets {
						wg.Add(1)
						requestCount++

						go func(p *E2ETestPlugin, t *plugin.Target, reqID int) {
							defer wg.Done()

							// Acquire semaphore
							semaphore <- struct{}{}
							defer func() { <-semaphore }()

							request := &plugin.AssessRequest{
								RequestID: fmt.Sprintf("stress-%d", reqID),
								Target:    t,
								Config: &plugin.AssessmentConfig{
									Domain: p.GetDomain(),
								},
							}

							result := p.Execute(ctx, request)
							success := result.IsOk() && result.Unwrap().Success
							results <- success
						}(plugin, target, requestCount)
					}
				}

				// Small delay between iterations
				time.Sleep(100 * time.Millisecond)
			}

			wg.Wait()
			close(results)

			// Collect results
			successCount := 0
			totalCount := 0
			for success := range results {
				totalCount++
				if success {
					successCount++
				}
			}

			actualDuration := time.Since(startTime)
			throughput := float64(totalCount) / actualDuration.Seconds()
			successRate := float64(successCount) / float64(totalCount)

			t.Logf("%s Stress Test Results:", tc.name)
			t.Logf("- Total requests: %d", totalCount)
			t.Logf("- Successful requests: %d", successCount)
			t.Logf("- Success rate: %.2f%%", successRate*100)
			t.Logf("- Duration: %v", actualDuration)
			t.Logf("- Throughput: %.2f req/sec", throughput)
			t.Logf("- Concurrency: %d", tc.concurrency)

			// Performance assertions
			assert.True(t, successRate >= 0.90, "Success rate should be at least 90% under stress")
			assert.True(t, throughput > 10.0, "Should maintain reasonable throughput")
			assert.True(t, totalCount > 0, "Should execute requests")
		})
	}
}

// TestE2E_MemoryAndResourceManagement tests resource management under load
func TestE2E_MemoryAndResourceManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E resource management test in short mode")
	}

	ctx := context.Background()
	plugin := NewE2ETestPlugin("resource-test-plugin", plugin.DomainInterface)

	// Measure baseline memory
	runtime.GC()
	var baselineMemStats runtime.MemStats
	runtime.ReadMemStats(&baselineMemStats)

	numRequests := 1000
	concurrency := 50

	t.Run("MemoryLeakTest", func(t *testing.T) {
		semaphore := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(requestID int) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				request := &plugin.AssessRequest{
					RequestID: fmt.Sprintf("memory-test-%d", requestID),
					Target: &plugin.Target{
						ID:   fmt.Sprintf("memory-target-%d", requestID),
						Name: "Memory Test Target",
						Type: "api",
						Configuration: map[string]string{
							"large_data": string(make([]byte, 1024)), // 1KB per request
						},
					},
					Config: &plugin.AssessmentConfig{
						Domain: plugin.DomainInterface,
					},
				}

				result := plugin.Execute(ctx, request)
				if result.IsErr() {
					t.Errorf("Request %d failed: %v", requestID, result.Error())
				}
			}(i)
		}

		wg.Wait()

		// Force garbage collection and measure memory
		runtime.GC()
		runtime.GC() // Run twice to ensure cleanup
		var finalMemStats runtime.MemStats
		runtime.ReadMemStats(&finalMemStats)

		memoryIncrease := finalMemStats.Alloc - baselineMemStats.Alloc
		maxMemoryIncrease := uint64(100 * 1024 * 1024) // 100MB threshold

		t.Logf("Memory Management Results:")
		t.Logf("- Baseline memory: %d bytes", baselineMemStats.Alloc)
		t.Logf("- Final memory: %d bytes", finalMemStats.Alloc)
		t.Logf("- Memory increase: %d bytes (%.2f MB)", memoryIncrease, float64(memoryIncrease)/(1024*1024))
		t.Logf("- Total allocations: %d", finalMemStats.TotalAlloc-baselineMemStats.TotalAlloc)
		t.Logf("- GC cycles: %d", finalMemStats.NumGC-baselineMemStats.NumGC)

		assert.True(t, memoryIncrease < maxMemoryIncrease, "Memory increase should be within acceptable limits")
	})

	t.Run("GoroutineLeakTest", func(t *testing.T) {
		baselineGoroutines := runtime.NumGoroutine()

		// Execute many concurrent requests
		semaphore := make(chan struct{}, 100)
		var wg sync.WaitGroup

		for i := 0; i < 500; i++ {
			wg.Add(1)
			go func(requestID int) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				request := &plugin.AssessRequest{
					RequestID: fmt.Sprintf("goroutine-test-%d", requestID),
					Target: &plugin.Target{
						ID:   "goroutine-target",
						Name: "Goroutine Test Target",
						Type: "api",
					},
					Config: &plugin.AssessmentConfig{
						Domain: plugin.DomainInterface,
					},
				}

				plugin.Execute(ctx, request)
			}(i)
		}

		wg.Wait()

		// Allow time for cleanup
		time.Sleep(100 * time.Millisecond)
		runtime.GC()

		finalGoroutines := runtime.NumGoroutine()
		goroutineIncrease := finalGoroutines - baselineGoroutines
		maxGoroutineIncrease := 10 // Allow some variance

		t.Logf("Goroutine Management Results:")
		t.Logf("- Baseline goroutines: %d", baselineGoroutines)
		t.Logf("- Final goroutines: %d", finalGoroutines)
		t.Logf("- Goroutine increase: %d", goroutineIncrease)

		assert.True(t, goroutineIncrease <= maxGoroutineIncrease, "Should not leak goroutines")
	})
}

// TestE2E_ProductionRedinessValidation validates production readiness
func TestE2E_ProductionReadinessValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("APIComplianceValidation", func(t *testing.T) {
		plugin := NewE2ETestPlugin("compliance-plugin", plugin.DomainInterface)

		// Test all required interface methods
		t.Run("GetInfo", func(t *testing.T) {
			result := plugin.GetInfo(ctx)
			require.True(t, result.IsOk(), "GetInfo must work")

			info := result.Unwrap()
			assert.NotEmpty(t, info.Name, "Plugin must have name")
			assert.NotEmpty(t, info.Version, "Plugin must have version")
			assert.NotEmpty(t, info.Author, "Plugin must have author")
			assert.NotEmpty(t, info.SupportedPayloadTypes, "Plugin must support payload types")
			assert.NotNil(t, info.Capabilities, "Plugin must define capabilities")
		})

		t.Run("Health", func(t *testing.T) {
			result := plugin.Health(ctx)
			require.True(t, result.IsOk(), "Health check must work")

			health := result.Unwrap()
			assert.Equal(t, plugin.HealthStatusHealthy, health.Status, "Plugin must report healthy status")
			assert.NotEmpty(t, health.Message, "Health check must include message")
			assert.False(t, health.Timestamp.IsZero(), "Health check must include timestamp")
		})

		t.Run("Validate", func(t *testing.T) {
			request := &plugin.AssessRequest{
				RequestID: "compliance-test",
				Target: &plugin.Target{
					ID:   "compliance-target",
					Name: "Compliance Target",
					Type: "api",
				},
				Config: &plugin.AssessmentConfig{
					Domain: plugin.DomainInterface,
				},
			}

			result := plugin.Validate(ctx, request)
			require.True(t, result.IsOk(), "Validate must work")

			validation := result.Unwrap()
			assert.True(t, validation.Valid, "Valid request must pass validation")
		})

		t.Run("Execute", func(t *testing.T) {
			request := &plugin.AssessRequest{
				RequestID: "compliance-execute-test",
				Target: &plugin.Target{
					ID:   "compliance-target",
					Name: "Compliance Target",
					Type: "api",
				},
				Config: &plugin.AssessmentConfig{
					Domain: plugin.DomainInterface,
				},
			}

			result := plugin.Execute(ctx, request)
			require.True(t, result.IsOk(), "Execute must work")

			response := result.Unwrap()
			assert.True(t, response.Success, "Execution must succeed")
			assert.True(t, response.Completed, "Execution must complete")
			assert.Equal(t, request.RequestID, response.RequestID, "Response must include request ID")
			assert.NotNil(t, response.ResourceUsage, "Must report resource usage")
		})
	})

	t.Run("SecurityValidation", func(t *testing.T) {
		validator := validation.NewValidator().WithStrictMode(true)

		// Test payload validation with various security patterns
		testPayloads := []struct {
			name        string
			payload     string
			shouldFail  bool
			description string
		}{
			{"Safe Input", "normal user input", false, "Safe input should pass"},
			{"SQL Injection", "'; DROP TABLE users; --", true, "SQL injection should be detected"},
			{"XSS Attack", "<script>alert('xss')</script>", true, "XSS should be detected"},
			{"Command Injection", "; rm -rf /", true, "Command injection should be detected"},
			{"Path Traversal", "../../etc/passwd", false, "Path traversal might be valid in some contexts"},
		}

		for _, tc := range testPayloads {
			t.Run(tc.name, func(t *testing.T) {
				result := validator.ValidatePayload(tc.payload)
				if tc.shouldFail {
					assert.True(t, result.HasErrors(), tc.description)
				} else {
					assert.False(t, result.HasErrors(), tc.description)
				}
			})
		}
	})
}

// Benchmark production scenarios
func BenchmarkE2E_ProductionScenario(b *testing.B) {
	ctx := context.Background()
	plugin := NewE2ETestPlugin("production-benchmark", plugin.DomainInterface)
	plugin.SetSimulatedLatency(2 * time.Millisecond) // Realistic latency

	request := &plugin.AssessRequest{
		RequestID: "production-benchmark",
		Target: &plugin.Target{
			ID:   "production-target",
			Name: "Production Target",
			Type: "api",
		},
		Config: &plugin.AssessmentConfig{
			Domain: plugin.DomainInterface,
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := plugin.Execute(ctx, request)
			if result.IsErr() {
				b.Fatal(result.Error())
			}
		}
	})
}