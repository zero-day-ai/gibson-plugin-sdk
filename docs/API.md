# Gibson Plugin SDK API Reference

The Gibson Plugin SDK provides a comprehensive set of interfaces and types for developing security plugins for the Gibson Framework. This document serves as the complete API reference for plugin developers.

## Table of Contents

- [Core Interfaces](#core-interfaces)
- [Data Models](#data-models)
- [Result Pattern](#result-pattern)
- [Security Domains](#security-domains)
- [gRPC Communication](#grpc-communication)
- [Testing Framework](#testing-framework)
- [Validation](#validation)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Core Interfaces

### SecurityPlugin

The primary interface that all Gibson security plugins must implement.

```go
type SecurityPlugin interface {
    // GetInfo returns plugin metadata including name, version, and capabilities
    GetInfo(ctx context.Context) models.Result[*PluginInfo]

    // Execute performs a security assessment on the given target
    Execute(ctx context.Context, request *AssessRequest) models.Result[*AssessResponse]

    // Validate checks if the plugin configuration and target are valid
    Validate(ctx context.Context, request *AssessRequest) models.Result[*ValidationResult]

    // Health performs a health check on the plugin
    Health(ctx context.Context) models.Result[*HealthStatus]
}
```

#### Usage Example

```go
package main

import (
    "context"
    "github.com/gibson-sec/gibson-plugin-sdk/pkg/plugin"
    "github.com/gibson-sec/gibson-plugin-sdk/pkg/core/models"
)

type MyPlugin struct {
    plugin.BasePlugin
}

func (p *MyPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
    // Perform security assessment
    findings := []*plugin.Finding{
        {
            ID:          "finding-1",
            Title:       "SQL Injection Vulnerability",
            Description: "Detected potential SQL injection in login form",
            Severity:    plugin.SeverityHigh,
            Domain:      plugin.DomainInterface,
        },
    }

    response := &plugin.AssessResponse{
        Success:   true,
        Completed: true,
        Findings:  findings,
        RequestID: request.RequestID,
    }

    return models.Ok(response)
}
```

### StreamingPlugin

Extends SecurityPlugin to support streaming assessments for long-running operations.

```go
type StreamingPlugin interface {
    SecurityPlugin

    // ExecuteStreaming performs a security assessment with streaming results
    ExecuteStreaming(ctx context.Context, request *AssessRequest, resultChan chan<- models.Result[*Finding]) models.Result[*AssessResponse]

    // SupportsStreaming returns true if the plugin supports streaming execution
    SupportsStreaming() bool
}
```

#### Usage Example

```go
func (p *MyStreamingPlugin) ExecuteStreaming(ctx context.Context, request *plugin.AssessRequest, resultChan chan<- models.Result[*plugin.Finding]) models.Result[*plugin.AssessResponse] {
    go func() {
        defer close(resultChan)

        // Stream findings as they're discovered
        for i := 0; i < 10; i++ {
            finding := &plugin.Finding{
                ID:       fmt.Sprintf("finding-%d", i),
                Title:    fmt.Sprintf("Issue %d", i),
                Severity: plugin.SeverityMedium,
            }

            select {
            case resultChan <- models.Ok(finding):
            case <-ctx.Done():
                return
            }
        }
    }()

    return models.Ok(&plugin.AssessResponse{
        Success:   true,
        Completed: true,
    })
}
```

### BatchPlugin

Extends SecurityPlugin to support batch processing of multiple targets.

```go
type BatchPlugin interface {
    SecurityPlugin

    // ExecuteBatch performs security assessments on multiple targets
    ExecuteBatch(ctx context.Context, requests []*AssessRequest) models.Result[*BatchAssessResponse]

    // GetOptimalBatchSize returns the recommended batch size for this plugin
    GetOptimalBatchSize() int

    // SupportsBatch returns true if the plugin supports batch execution
    SupportsBatch() bool
}
```

### ConfigurablePlugin

Extends SecurityPlugin to support dynamic configuration.

```go
type ConfigurablePlugin interface {
    SecurityPlugin

    // GetConfigSchema returns the configuration schema for this plugin
    GetConfigSchema(ctx context.Context) models.Result[*ConfigSchema]

    // UpdateConfig updates the plugin configuration
    UpdateConfig(ctx context.Context, config map[string]interface{}) models.Result[bool]

    // GetCurrentConfig returns the current plugin configuration
    GetCurrentConfig(ctx context.Context) models.Result[map[string]interface{}]
}
```

### BasePlugin

Provides a default implementation that can be embedded in plugin implementations to reduce boilerplate.

```go
type BasePlugin struct {
    info   *PluginInfo
    config map[string]interface{}
}

func NewBasePlugin(info *PluginInfo) *BasePlugin
func (p *BasePlugin) GetInfo(ctx context.Context) models.Result[*PluginInfo]
func (p *BasePlugin) Health(ctx context.Context) models.Result[*HealthStatus]
func (p *BasePlugin) Validate(ctx context.Context, request *AssessRequest) models.Result[*ValidationResult]
```

## Data Models

### PluginInfo

Contains metadata about a security plugin.

```go
type PluginInfo struct {
    Name                   string                 `json:"name"`
    Version                string                 `json:"version"`
    Description            string                 `json:"description"`
    Author                 string                 `json:"author"`
    Domain                 SecurityDomain         `json:"domain"`
    SupportedPayloadTypes  []PayloadType          `json:"supported_payload_types"`
    Capabilities           *PluginCapabilities    `json:"capabilities"`
    Metadata               map[string]string      `json:"metadata"`
    CreatedAt              time.Time              `json:"created_at"`
    UpdatedAt              time.Time              `json:"updated_at"`
}
```

### AssessRequest

Contains the target and configuration for security assessment.

```go
type AssessRequest struct {
    RequestID string              `json:"request_id"`
    Target    *Target             `json:"target"`
    Config    *AssessmentConfig   `json:"config"`
    Context   map[string]string   `json:"context"`
}
```

### Target

Represents the system, API, or resource being assessed.

```go
type Target struct {
    ID            string            `json:"id"`
    Name          string            `json:"name"`
    Type          string            `json:"type"`
    Endpoint      string            `json:"endpoint"`
    Configuration map[string]string `json:"configuration"`
    Credentials   *Credentials      `json:"credentials,omitempty"`
    Tags          []string          `json:"tags,omitempty"`
    Metadata      map[string]string `json:"metadata,omitempty"`
}
```

### AssessResponse

Contains the results of a security assessment.

```go
type AssessResponse struct {
    Success       bool              `json:"success"`
    Error         string            `json:"error,omitempty"`
    Completed     bool              `json:"completed"`
    Findings      []*Finding        `json:"findings"`
    StartTime     time.Time         `json:"start_time"`
    EndTime       time.Time         `json:"end_time"`
    Duration      time.Duration     `json:"duration"`
    Metadata      map[string]string `json:"metadata"`
    ResourceUsage *ResourceUsage    `json:"resource_usage,omitempty"`
    RequestID     string            `json:"request_id"`
}
```

### Finding

Represents a security vulnerability or issue discovered during assessment.

```go
type Finding struct {
    ID          string            `json:"id"`
    Title       string            `json:"title"`
    Description string            `json:"description"`
    Severity    SeverityLevel     `json:"severity"`
    Domain      SecurityDomain    `json:"domain"`
    PayloadType PayloadType       `json:"payload_type"`
    Payload     string            `json:"payload,omitempty"`
    Location    string            `json:"location,omitempty"`
    Evidence    *Evidence         `json:"evidence,omitempty"`
    Remediation *Remediation      `json:"remediation,omitempty"`
    Tags        []string          `json:"tags,omitempty"`
    Metadata    map[string]string `json:"metadata,omitempty"`
    DiscoveredAt time.Time        `json:"discovered_at"`
}
```

## Result Pattern

The SDK uses a functional Result[T] pattern for consistent error handling.

### Result[T] Type

```go
type Result[T any] struct {
    value T
    err   error
}
```

### Methods

```go
// Create results
func Ok[T any](value T) Result[T]
func Err[T any](err error) Result[T]

// Check status
func (r Result[T]) IsOk() bool
func (r Result[T]) IsErr() bool

// Access values
func (r Result[T]) Unwrap() T
func (r Result[T]) UnwrapOr(defaultValue T) T
func (r Result[T]) Error() error
```

### Usage Examples

```go
// Creating results
successResult := models.Ok("success value")
errorResult := models.Err[string](errors.New("something went wrong"))

// Checking and unwrapping
if result.IsOk() {
    value := result.Unwrap()
    // use value
} else {
    err := result.Error()
    // handle error
}

// Using default values
value := result.UnwrapOr("default value")
```

## Security Domains

The SDK defines six security domains for categorizing plugins and findings.

### SecurityDomain Type

```go
type SecurityDomain string

const (
    DomainModel          SecurityDomain = "model"
    DomainData           SecurityDomain = "data"
    DomainInterface      SecurityDomain = "interface"
    DomainInfrastructure SecurityDomain = "infrastructure"
    DomainOutput         SecurityDomain = "output"
    DomainProcess        SecurityDomain = "process"
)
```

### Domain Descriptions

- **Model**: AI model-specific attacks (prompt injection, model extraction, etc.)
- **Data**: Data-centric security assessments (data poisoning, privacy leaks, etc.)
- **Interface**: Interface and interaction vulnerabilities (input validation, XSS, etc.)
- **Infrastructure**: System and infrastructure security (configuration, access control, etc.)
- **Output**: Output security and content validation (output filtering, content safety, etc.)
- **Process**: Operational and governance security (audit trails, compliance, etc.)

### Payload Types

```go
type PayloadType string

const (
    PayloadTypePrompt PayloadType = "prompt"
    PayloadTypeQuery  PayloadType = "query"
    PayloadTypeInput  PayloadType = "input"
    PayloadTypeCode   PayloadType = "code"
    PayloadTypeData   PayloadType = "data"
    PayloadTypeScript PayloadType = "script"
)
```

## Severity and Confidence Levels

### SeverityLevel

```go
type SeverityLevel string

const (
    SeverityCritical SeverityLevel = "critical"
    SeverityHigh     SeverityLevel = "high"
    SeverityMedium   SeverityLevel = "medium"
    SeverityLow      SeverityLevel = "low"
    SeverityInfo     SeverityLevel = "info"
)
```

### ConfidenceLevel

```go
type ConfidenceLevel string

const (
    ConfidenceHigh   ConfidenceLevel = "high"
    ConfidenceMedium ConfidenceLevel = "medium"
    ConfidenceLow    ConfidenceLevel = "low"
)
```

## gRPC Communication

The SDK uses gRPC for process-isolated plugin execution.

### gRPC Server

```go
type GRPCServer struct {
    plugin SecurityPlugin
}

func NewGRPCServer(plugin SecurityPlugin) *GRPCServer
func (s *GRPCServer) GetInfo(ctx context.Context, req *proto.GetInfoRequest) (*proto.GetInfoResponse, error)
func (s *GRPCServer) Execute(ctx context.Context, req *proto.ExecuteRequest) (*proto.ExecuteResponse, error)
func (s *GRPCServer) Health(ctx context.Context, req *proto.HealthRequest) (*proto.HealthResponse, error)
```

### gRPC Client

```go
type GRPCClient struct {
    client proto.SecurityPluginClient
}

func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient
func (c *GRPCClient) GetInfo(ctx context.Context) models.Result[*PluginInfo]
func (c *GRPCClient) Execute(ctx context.Context, request *AssessRequest) models.Result[*AssessResponse]
func (c *GRPCClient) Health(ctx context.Context) models.Result[*HealthStatus]
```

### Plugin Handshake

```go
var HandshakeConfig = plugin.HandshakeConfig{
    ProtocolVersion:  1,
    MagicCookieKey:   "GIBSON_PLUGIN",
    MagicCookieValue: "gibson-security-plugin",
}
```

## Testing Framework

### PluginTestHarness

Comprehensive testing framework for plugin validation.

```go
type PluginTestHarness struct {
    plugin SecurityPlugin
    config TestConfig
}

func NewPluginTestHarness(plugin SecurityPlugin, config TestConfig) *PluginTestHarness
func (h *PluginTestHarness) RunComplianceTests(ctx context.Context) *TestResults
func (h *PluginTestHarness) RunPerformanceTests(ctx context.Context) *PerformanceResults
func (h *PluginTestHarness) RunSecurityTests(ctx context.Context) *SecurityTestResults
```

### Mock Plugin

```go
type MockPlugin struct {
    InfoResult     models.Result[*PluginInfo]
    ExecuteResult  models.Result[*AssessResponse]
    ValidateResult models.Result[*ValidationResult]
    HealthResult   models.Result[*HealthStatus]
}

func NewMockPlugin() *MockPlugin
func (m *MockPlugin) SetExecuteResult(result models.Result[*AssessResponse])
func (m *MockPlugin) GetExecuteCallCount() int
```

## Validation

### Input Validation

```go
func ValidateAssessRequest(request *AssessRequest) error
func ValidateTarget(target *Target) error
func ValidateFinding(finding *Finding) error
func ValidatePluginInfo(info *PluginInfo) error
```

### Security Validation

```go
func ValidateInputSafety(input string) error
func ValidateOutputSafety(output string) error
func ValidatePayloadSafety(payload string) error
```

### Configuration Validation

```go
func ValidatePluginConfig(config map[string]interface{}, schema *ConfigSchema) error
```

## Error Handling

### Plugin Errors

```go
var (
    ErrPluginNotInitialized = errors.New("plugin not initialized")
    ErrInvalidRequest      = errors.New("invalid assessment request")
    ErrInvalidTarget       = errors.New("invalid target configuration")
    ErrInvalidConfig       = errors.New("invalid plugin configuration")
    ErrExecutionTimeout    = errors.New("plugin execution timeout")
    ErrExecutionFailed     = errors.New("plugin execution failed")
)
```

### Error Wrapping

```go
func WrapError(err error, msg string) error
func IsPluginError(err error) bool
func GetPluginErrorType(err error) string
```

## Examples

### Basic Plugin Implementation

```go
package main

import (
    "context"
    "time"

    "github.com/gibson-sec/gibson-plugin-sdk/pkg/plugin"
    "github.com/gibson-sec/gibson-plugin-sdk/pkg/core/models"
)

type BasicSecurityPlugin struct {
    *plugin.BasePlugin
}

func NewBasicSecurityPlugin() *BasicSecurityPlugin {
    info := &plugin.PluginInfo{
        Name:        "basic-security-plugin",
        Version:     "1.0.0",
        Description: "A basic security testing plugin",
        Author:      "Security Team",
        Domain:      plugin.DomainInterface,
        SupportedPayloadTypes: []plugin.PayloadType{
            plugin.PayloadTypeInput,
            plugin.PayloadTypeQuery,
        },
        Capabilities: &plugin.PluginCapabilities{
            SupportsStreaming:     false,
            SupportsBatch:         true,
            MaxConcurrentRequests: 10,
            TimeoutSeconds:        30,
        },
    }

    return &BasicSecurityPlugin{
        BasePlugin: plugin.NewBasePlugin(info),
    }
}

func (p *BasicSecurityPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
    // Validate request
    if validationResult := p.Validate(ctx, request); validationResult.IsErr() {
        return models.Err[*plugin.AssessResponse](validationResult.Error())
    }

    startTime := time.Now()

    // Perform security assessment
    findings := []*plugin.Finding{}

    // Example: Check for SQL injection patterns
    if p.checkSQLInjection(request.Target) {
        finding := &plugin.Finding{
            ID:          "sql-injection-1",
            Title:       "Potential SQL Injection",
            Description: "Found potential SQL injection vulnerability",
            Severity:    plugin.SeverityHigh,
            Domain:      plugin.DomainInterface,
            PayloadType: plugin.PayloadTypeQuery,
            DiscoveredAt: time.Now(),
        }
        findings = append(findings, finding)
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
        Metadata:  map[string]string{
            "checks_performed": "sql_injection,xss,command_injection",
        },
    }

    return models.Ok(response)
}

func (p *BasicSecurityPlugin) checkSQLInjection(target *plugin.Target) bool {
    // Implementation for SQL injection detection
    return false
}

func main() {
    plugin := NewBasicSecurityPlugin()

    // Set up gRPC server for plugin communication
    server := grpc.NewServer()
    proto.RegisterSecurityPluginServer(server, NewGRPCServer(plugin))

    // Start serving
    listener, _ := net.Listen("tcp", ":50051")
    server.Serve(listener)
}
```

### Streaming Plugin Implementation

```go
func (p *StreamingPlugin) ExecuteStreaming(ctx context.Context, request *plugin.AssessRequest, resultChan chan<- models.Result[*plugin.Finding]) models.Result[*plugin.AssessResponse] {
    go func() {
        defer close(resultChan)

        payloads := []string{"' OR 1=1--", "<script>alert('xss')</script>", "$(rm -rf /)"}

        for _, payload := range payloads {
            select {
            case <-ctx.Done():
                return
            default:
                // Test payload
                if p.testPayload(request.Target, payload) {
                    finding := &plugin.Finding{
                        ID:          fmt.Sprintf("finding-%s", payload),
                        Title:       "Security Vulnerability",
                        Description: fmt.Sprintf("Payload succeeded: %s", payload),
                        Severity:    plugin.SeverityHigh,
                        Payload:     payload,
                        DiscoveredAt: time.Now(),
                    }

                    resultChan <- models.Ok(finding)
                }

                time.Sleep(100 * time.Millisecond) // Simulate processing time
            }
        }
    }()

    return models.Ok(&plugin.AssessResponse{
        Success:   true,
        Completed: false, // Will complete when stream finishes
        RequestID: request.RequestID,
    })
}
```

### Testing Plugin Implementation

```go
func TestPluginCompliance(t *testing.T) {
    plugin := NewBasicSecurityPlugin()
    harness := testing.NewPluginTestHarness(plugin, testing.TestConfig{
        Timeout:         30 * time.Second,
        MaxFindings:     100,
        RequiredMethods: []string{"GetInfo", "Execute", "Health", "Validate"},
    })

    ctx := context.Background()
    results := harness.RunComplianceTests(ctx)

    if !results.Passed {
        t.Errorf("Plugin compliance tests failed: %v", results.Failures)
    }

    // Test specific functionality
    request := &plugin.AssessRequest{
        RequestID: "test-request",
        Target: &plugin.Target{
            ID:   "test-target",
            Name: "Test Target",
            Type: "api",
            Endpoint: "https://api.example.com",
        },
    }

    result := plugin.Execute(ctx, request)
    if result.IsErr() {
        t.Errorf("Plugin execution failed: %v", result.Error())
    }

    response := result.Unwrap()
    if !response.Success {
        t.Errorf("Assessment failed: %s", response.Error)
    }
}
```

## Best Practices

### Error Handling

- Always use the Result[T] pattern for consistent error handling
- Wrap errors with context using WrapError()
- Return meaningful error messages for debugging

### Performance

- Implement timeout handling in all operations
- Use streaming for long-running assessments
- Implement batch processing for multiple targets
- Monitor resource usage and implement limits

### Security

- Validate all inputs using the validation package
- Never log sensitive information (credentials, tokens)
- Implement proper authentication and authorization
- Use secure communication (TLS) for gRPC

### Testing

- Use the PluginTestHarness for comprehensive testing
- Write unit tests for all plugin methods
- Test error conditions and edge cases
- Validate compliance with plugin interfaces

This API reference provides complete documentation for developing Gibson Framework security plugins. For additional examples and guides, see the [examples directory](../examples/) and [plugin development guide](../guides/plugin-development.md).