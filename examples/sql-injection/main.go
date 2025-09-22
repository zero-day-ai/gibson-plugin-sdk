package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/grpc"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
)

// SQLInjectionPlugin demonstrates SQL injection testing capabilities
type SQLInjectionPlugin struct {
	*plugin.BasePlugin
	payloads []string
}

// NewSQLInjectionPlugin creates a new SQL injection testing plugin
func NewSQLInjectionPlugin() *SQLInjectionPlugin {
	info := &plugin.PluginInfo{
		Name:        "sql-injection-tester",
		Version:     "1.0.0",
		Description: "SQL injection vulnerability detection plugin",
		Author:      "Gibson SDK Team",
		Domain:      plugin.DomainInterface,
		SupportedPayloadTypes: []plugin.PayloadType{
			plugin.PayloadTypeQuery,
			plugin.PayloadTypeInput,
			plugin.PayloadTypeCode,
		},
		Capabilities: &plugin.PluginCapabilities{
			SupportsStreaming:     false,
			SupportsBatch:         true,
			SupportsConcurrent:    true,
			MaxConcurrentRequests: 5,
			TimeoutSeconds:        60,
			RequiredPermissions:   []string{"network.http"},
		},
		Metadata: map[string]string{
			"category": "injection",
			"tags":     "sql,injection,security",
			"cve_refs": "CWE-89",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Common SQL injection payloads
	payloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"'; DROP TABLE users--",
		"' UNION SELECT * FROM users--",
		"admin'--",
		"' OR 'x'='x",
		"1' OR '1'='1' /*",
		"x' AND email IS NULL; --",
		"0' UNION SELECT NULL,username,password FROM users--",
		"' OR (SELECT COUNT(*) FROM users) > 0--",
	}

	return &SQLInjectionPlugin{
		BasePlugin: plugin.NewBasePlugin(info),
		payloads:   payloads,
	}
}

// Execute performs SQL injection testing
func (p *SQLInjectionPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
	// Validate the request
	validationResult := p.Validate(ctx, request)
	if validationResult.IsErr() {
		return models.Err[*plugin.AssessResponse](validationResult.Error())
	}

	validation := validationResult.Unwrap()
	if !validation.Valid {
		return models.Ok(&plugin.AssessResponse{
			Success:   false,
			Error:     validation.Message,
			RequestID: request.RequestID,
		})
	}

	startTime := time.Now()
	var findings []*plugin.Finding

	// Test each SQL injection payload
	for i, payload := range p.payloads {
		// Simulate testing the payload
		select {
		case <-ctx.Done():
			// Context cancelled, return partial results
			break
		default:
			// Continue testing
		}

		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)

		// For demonstration, create findings for certain payloads
		if p.isVulnerable(payload, request.Target) {
			finding := &plugin.Finding{
				ID:          fmt.Sprintf("SQLI-%03d", i+1),
				Title:       "SQL Injection Vulnerability Detected",
				Description: fmt.Sprintf("The target appears vulnerable to SQL injection using payload: %s", payload),
				Severity:    p.getSeverityForPayload(payload),
				Domain:      plugin.DomainInterface,
				PayloadType: plugin.PayloadTypeQuery,
				Payload:     payload,
				Location:    request.Target.Endpoint,
				Evidence: &plugin.Evidence{
					Type: "injection_response",
					Data: fmt.Sprintf("Payload '%s' produced unexpected response", payload),
					Context: map[string]string{
						"payload":     payload,
						"target_type": request.Target.Type,
						"method":      "automated_testing",
					},
				},
				Remediation: &plugin.Remediation{
					Description: "Implement parameterized queries and input validation",
					Steps: []string{
						"Replace dynamic SQL with parameterized queries",
						"Implement strict input validation",
						"Use prepared statements",
						"Apply principle of least privilege for database access",
						"Regularly update and patch database systems",
					},
					Priority: "high",
					Effort:   "medium",
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://cwe.mitre.org/data/definitions/89.html",
					},
				},
				Tags: []string{"sql-injection", "injection", "database", "security"},
				Metadata: map[string]string{
					"payload_index": fmt.Sprintf("%d", i),
					"payload_type":  "sql_injection",
					"cwe_id":        "CWE-89",
				},
				DiscoveredAt: time.Now(),
			}
			findings = append(findings, finding)
		}

		// Limit findings to prevent overwhelming results
		if len(findings) >= 5 {
			break
		}
	}

	endTime := time.Now()

	response := &plugin.AssessResponse{
		Success:   true,
		Completed: true,
		Findings:  findings,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
		RequestID: request.RequestID,
		Metadata: map[string]string{
			"payloads_tested": fmt.Sprintf("%d", len(p.payloads)),
			"findings_count":  fmt.Sprintf("%d", len(findings)),
			"execution_time":  endTime.Sub(startTime).String(),
			"plugin_version":  "1.0.0",
			"test_type":       "sql_injection",
		},
	}

	return models.Ok(response)
}

// isVulnerable simulates vulnerability detection logic
func (p *SQLInjectionPlugin) isVulnerable(payload string, target *plugin.Target) bool {
	// This is a simulation - in a real plugin, you would:
	// 1. Send HTTP requests with the payload
	// 2. Analyze response patterns
	// 3. Look for SQL error messages
	// 4. Check for timing differences
	// 5. Verify boolean-based blind injection

	// For demo purposes, simulate some payloads being "detected"
	vulnerablePatterns := []string{
		"' OR '1'='1",
		"'; DROP TABLE",
		"UNION SELECT",
	}

	for _, pattern := range vulnerablePatterns {
		if strings.Contains(payload, pattern) {
			// Simulate a 30% chance of detection for demo
			return len(target.Endpoint)%3 == 0
		}
	}

	return false
}

// getSeverityForPayload determines severity based on payload type
func (p *SQLInjectionPlugin) getSeverityForPayload(payload string) plugin.SeverityLevel {
	if strings.Contains(payload, "DROP") || strings.Contains(payload, "DELETE") {
		return plugin.SeverityCritical
	}
	if strings.Contains(payload, "UNION") || strings.Contains(payload, "SELECT") {
		return plugin.SeverityHigh
	}
	return plugin.SeverityMedium
}

func main() {
	// Create the plugin instance
	plugin := NewSQLInjectionPlugin()

	// Serve the plugin using the Gibson SDK
	grpc.Serve(plugin)
}
