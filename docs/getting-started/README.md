# Getting Started with Gibson Plugin SDK

Welcome to the Gibson Plugin SDK! This guide will walk you through creating your first security assessment plugin from scratch.

## Prerequisites

- Go 1.21 or later
- Basic understanding of Go programming
- Familiarity with security assessment concepts

## Installation

First, create a new Go module for your plugin:

```bash
mkdir my-security-plugin
cd my-security-plugin
go mod init my-security-plugin
```

Add the Gibson Plugin SDK dependency:

```bash
go get github.com/zero-day-ai/gibson-sdk@latest
```

## Your First Plugin

Let's create a simple plugin that checks for a basic security header:

### 1. Create the Plugin Structure

Create a file called `main.go`:

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/zero-day-ai/gibson-sdk/pkg/plugin"
    "github.com/zero-day-ai/gibson-sdk/pkg/core/models"
    "github.com/zero-day-ai/gibson-sdk/pkg/grpc"
    "github.com/hashicorp/go-plugin"
    "github.com/google/uuid"
)

// SecurityHeaderPlugin checks for security headers
type SecurityHeaderPlugin struct {
    plugin.BasePlugin
}

// GetInfo returns plugin metadata
func (p *SecurityHeaderPlugin) GetInfo() models.Result[models.PluginInfo] {
    info := models.PluginInfo{
        Name:        "security-header-checker",
        Version:     "1.0.0",
        Domain:      plugin.SecurityDomainInterface,
        Description: "Checks for missing security headers",
        Author:      "Your Name",
        License:     "MIT",
        Tags:        []string{"headers", "web", "security"},
    }
    return models.Ok(info)
}

// Initialize sets up the plugin
func (p *SecurityHeaderPlugin) Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool] {
    // Plugin initialization logic here
    return models.Ok(true)
}

// Validate checks if the request is valid
func (p *SecurityHeaderPlugin) Validate(ctx context.Context, request models.AssessRequest) models.Result[bool] {
    if request.Target.URL == "" {
        return models.Err[bool](fmt.Errorf("target URL is required"))
    }
    return models.Ok(true)
}

// Execute performs the security assessment
func (p *SecurityHeaderPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    startTime := time.Now()

    // Create HTTP client
    client := &http.Client{
        Timeout: 10 * time.Second,
    }

    // Make request to target
    resp, err := client.Get(request.Target.URL)
    if err != nil {
        return models.Err[models.AssessResponse](fmt.Errorf("failed to connect to target: %w", err))
    }
    defer resp.Body.Close()

    // Check for security headers
    findings := p.checkSecurityHeaders(resp, request.Target.URL)

    response := models.AssessResponse{
        ID:         uuid.New(),
        PluginName: "security-header-checker",
        Status:     "completed",
        StartTime:  startTime,
        EndTime:    time.Now(),
        Findings:   findings,
        Metadata: map[string]interface{}{
            "target_url":    request.Target.URL,
            "status_code":   resp.StatusCode,
            "headers_found": len(resp.Header),
        },
    }

    return models.Ok(response)
}

// checkSecurityHeaders analyzes HTTP headers for security issues
func (p *SecurityHeaderPlugin) checkSecurityHeaders(resp *http.Response, url string) []models.Finding {
    var findings []models.Finding

    // Check for X-Frame-Options
    if resp.Header.Get("X-Frame-Options") == "" {
        findings = append(findings, models.Finding{
            ID:          uuid.New(),
            Title:       "Missing X-Frame-Options Header",
            Description: "The X-Frame-Options header is missing, which may allow clickjacking attacks",
            Severity:    plugin.SeverityMedium,
            Category:    plugin.PayloadCategoryInterface,
            Evidence: map[string]interface{}{
                "url":           url,
                "missing_header": "X-Frame-Options",
            },
            Recommendation: "Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'",
            References: []string{
                "https://owasp.org/www-project-secure-headers/#x-frame-options",
            },
            Tags:      []string{"clickjacking", "headers"},
            CreatedAt: time.Now(),
        })
    }

    // Check for X-Content-Type-Options
    if resp.Header.Get("X-Content-Type-Options") == "" {
        findings = append(findings, models.Finding{
            ID:          uuid.New(),
            Title:       "Missing X-Content-Type-Options Header",
            Description: "The X-Content-Type-Options header is missing, which may allow MIME type sniffing",
            Severity:    plugin.SeverityLow,
            Category:    plugin.PayloadCategoryInterface,
            Evidence: map[string]interface{}{
                "url":           url,
                "missing_header": "X-Content-Type-Options",
            },
            Recommendation: "Add X-Content-Type-Options header with value 'nosniff'",
            References: []string{
                "https://owasp.org/www-project-secure-headers/#x-content-type-options",
            },
            Tags:      []string{"mime-sniffing", "headers"},
            CreatedAt: time.Now(),
        })
    }

    return findings
}

// Cleanup releases resources
func (p *SecurityHeaderPlugin) Cleanup(ctx context.Context) models.Result[bool] {
    // Cleanup logic here
    return models.Ok(true)
}

func main() {
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: grpc.HandshakeConfig,
        Plugins: map[string]plugin.Plugin{
            "security": &grpc.SecurityPluginGRPC{Impl: &SecurityHeaderPlugin{}},
        },
        GRPCServer: plugin.DefaultGRPCServer,
    })
}
```

### 2. Build Your Plugin

```bash
go build -o security-header-plugin main.go
```

### 3. Test Your Plugin

Create a test file `main_test.go`:

```go
package main

import (
    "context"
    "testing"

    "github.com/zero-day-ai/gibson-sdk/pkg/testing"
    "github.com/zero-day-ai/gibson-sdk/pkg/core/models"
    "github.com/zero-day-ai/gibson-sdk/pkg/plugin"
)

func TestSecurityHeaderPlugin(t *testing.T) {
    // Create plugin instance
    p := &SecurityHeaderPlugin{}

    // Create test harness
    harness := testing.NewPluginTestHarness()

    // Test compliance
    result := harness.TestCompliance(p)
    if !result.Passed {
        t.Errorf("Plugin compliance test failed: %v", result.Errors)
    }

    // Test with fixtures
    fixtures := testing.NewTestFixtures()
    request := fixtures.ValidAssessRequest()
    request.Target.URL = "https://example.com"

    // Test execution
    response := p.Execute(context.Background(), request)
    if response.IsErr() {
        t.Errorf("Plugin execution failed: %v", response.Error())
    }

    assessResponse := response.Unwrap()
    if assessResponse.Status != "completed" {
        t.Errorf("Expected status 'completed', got %s", assessResponse.Status)
    }
}
```

Run the tests:

```bash
go test ./...
```

## Understanding the Plugin Structure

### Core Interface Methods

Every security plugin must implement these methods:

1. **GetInfo()**: Returns plugin metadata
2. **Initialize()**: Sets up the plugin with configuration
3. **Validate()**: Validates the assessment request
4. **Execute()**: Performs the actual security assessment
5. **Cleanup()**: Releases resources after assessment

### Result[T] Pattern

The SDK uses a functional error handling pattern with `Result[T]`:

```go
// Success case
return models.Ok(response)

// Error case
return models.Err[ResponseType](fmt.Errorf("something went wrong"))

// Checking results
result := someFunction()
if result.IsErr() {
    log.Printf("Error: %v", result.Error())
    return
}
value := result.Unwrap()
```

### Security Domains

Choose the appropriate domain for your plugin:

- `SecurityDomainModel`: AI/ML model security
- `SecurityDomainData`: Data security and privacy
- `SecurityDomainInterface`: User interface security
- `SecurityDomainInfrastructure`: System security
- `SecurityDomainOutput`: Output validation
- `SecurityDomainProcess`: Process and governance

## Next Steps

1. **Read the [Plugin Development Guide](../guides/plugin-development.md)** for advanced techniques
2. **Explore [Examples](../../examples/)** for more complex plugin implementations
3. **Check the [API Reference](../API.md)** for complete documentation
4. **Learn about [Testing](../guides/testing.md)** for comprehensive test coverage

## Common Patterns

### Configuration Handling

```go
func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool] {
    timeout := 30 * time.Second
    if timeoutVal, ok := config["timeout"]; ok {
        if t, ok := timeoutVal.(string); ok {
            if duration, err := time.ParseDuration(t); err == nil {
                timeout = duration
            }
        }
    }

    p.timeout = timeout
    return models.Ok(true)
}
```

### Error Handling

```go
func (p *MyPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    // Validate input
    if request.Target.URL == "" {
        return models.Err[models.AssessResponse](fmt.Errorf("target URL is required"))
    }

    // Perform assessment with error handling
    findings, err := p.performAssessment(request.Target.URL)
    if err != nil {
        return models.Err[models.AssessResponse](fmt.Errorf("assessment failed: %w", err))
    }

    // Return successful response
    response := models.AssessResponse{
        // ... populate response
    }
    return models.Ok(response)
}
```

### Context Handling

```go
func (p *MyPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    // Check for cancellation
    select {
    case <-ctx.Done():
        return models.Err[models.AssessResponse](ctx.Err())
    default:
    }

    // Use context with timeout
    ctx, cancel := context.WithTimeout(ctx, p.timeout)
    defer cancel()

    // Pass context to HTTP requests
    req, _ := http.NewRequestWithContext(ctx, "GET", request.Target.URL, nil)
    resp, err := p.client.Do(req)
    // ...
}
```

## Troubleshooting

### Common Issues

1. **Plugin doesn't load**: Check that all interface methods are implemented
2. **gRPC errors**: Ensure proper handshake configuration
3. **Test failures**: Verify that test fixtures are properly configured
4. **Performance issues**: Use context timeouts and connection pooling

### Debugging

Enable verbose logging:

```go
import "log/slog"

func (p *MyPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    slog.Info("Starting assessment", "target", request.Target.URL)
    // ... assessment logic
    slog.Info("Assessment completed", "findings", len(findings))
}
```

## Resources

- [Plugin Development Guide](../guides/plugin-development.md)
- [API Reference](../API.md)
- [Testing Guide](../guides/testing.md)
- [Migration Guide](../../MIGRATION.md)
- [Examples](../../examples/)

Happy plugin development! 🚀