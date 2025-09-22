# Gibson Plugin Migration Guide

This guide helps you migrate existing Gibson plugins from the shared package to the new Gibson Plugin SDK. The migration process updates your plugin to use the standalone SDK with improved architecture, better error handling, and enhanced functionality.

## Overview

The Gibson Plugin SDK v1.0 introduces several important changes:

- **Standalone SDK**: Plugins no longer depend on the Gibson Framework shared package
- **Result[T] Pattern**: Improved error handling using functional programming patterns
- **Enhanced Interfaces**: More robust plugin interfaces with better type safety
- **gRPC Communication**: Process-isolated plugin execution
- **Comprehensive Testing**: Built-in testing framework and mock implementations

## Migration Strategy

### Automatic Migration (Recommended)

Use the automated migration tool for most common scenarios:

```bash
# Download the migration tool
go install github.com/zero-day-ai/gibson-sdk/cmd/migrate@latest

# Preview changes (dry run)
gibson-migrate --plugin-dir ./my-plugin --dry-run --verbose

# Apply migration with backup
gibson-migrate --plugin-dir ./my-plugin --backup
```

### Manual Migration

For complex plugins or custom implementations, follow the manual migration steps below.

## Step-by-Step Migration

### Step 1: Update Dependencies

#### Update go.mod

Replace framework shared dependency with SDK:

```go
// Before
module my-awesome-plugin

go 1.21

require (
    github.com/gibson-sec/gibson-framework v1.5.0
)

// After
module my-awesome-plugin

go 1.21

require (
    github.com/zero-day-ai/gibson-sdk v1.0.0
)
```

#### Update go.sum

```bash
go mod tidy
```

### Step 2: Update Import Statements

Replace all shared package imports with SDK imports:

```go
// Before
import (
    "github.com/gibson-sec/gibson-framework/shared"
    "github.com/gibson-sec/gibson-framework/shared/models"
    "github.com/gibson-sec/gibson-framework/shared/types"
)

// After
import (
    "github.com/zero-day-ai/gibson-sdk/pkg/plugin"
    "github.com/zero-day-ai/gibson-sdk/pkg/core/models"
)
```

#### Complete Import Mapping

| Old Import | New Import |
|------------|------------|
| `github.com/gibson-sec/gibson-framework/shared` | `github.com/zero-day-ai/gibson-sdk/pkg/plugin` |
| `github.com/gibson-sec/gibson-framework/shared/models` | `github.com/zero-day-ai/gibson-sdk/pkg/core/models` |
| `github.com/gibson-sec/gibson-framework/shared/types` | `github.com/zero-day-ai/gibson-sdk/pkg/plugin` |
| `github.com/gibson-sec/gibson-framework/shared/errors` | `github.com/zero-day-ai/gibson-sdk/pkg/core/models` |

### Step 3: Update Plugin Interface Implementation

#### SecurityPlugin Interface

Update your plugin to implement the new `SecurityPlugin` interface:

```go
// Before
type MyPlugin struct {
    config map[string]interface{}
}

func (p *MyPlugin) GetInfo() (*shared.PluginInfo, error) {
    info := &shared.PluginInfo{
        Name:    "my-plugin",
        Version: "1.0.0",
    }
    return info, nil
}

func (p *MyPlugin) Execute(target *shared.Target, payload *shared.Payload) (*shared.SecurityResult, error) {
    // Implementation
    return result, nil
}

// After
type MyPlugin struct {
    plugin.BasePlugin
    config map[string]interface{}
}

func (p *MyPlugin) GetInfo() models.Result[models.PluginInfo] {
    info := models.PluginInfo{
        Name:    "my-plugin",
        Version: "1.0.0",
        Domain:  plugin.SecurityDomainInterface,
    }
    return models.Ok(info)
}

func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool] {
    p.config = config
    return models.Ok(true)
}

func (p *MyPlugin) Validate(ctx context.Context, request models.AssessRequest) models.Result[bool] {
    // Validation logic
    return models.Ok(true)
}

func (p *MyPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    // Implementation using new patterns
    response := models.AssessResponse{
        ID:         uuid.New(),
        PluginName: "my-plugin",
        Status:     "completed",
        // ... other fields
    }
    return models.Ok(response)
}

func (p *MyPlugin) Cleanup(ctx context.Context) models.Result[bool] {
    // Cleanup logic
    return models.Ok(true)
}
```

#### Complete Interface Methods

All plugins must implement these methods:

1. **GetInfo()** - Returns plugin metadata
2. **Initialize(ctx, config)** - Initializes plugin with configuration
3. **Validate(ctx, request)** - Validates assessment request
4. **Execute(ctx, request)** - Performs security assessment
5. **Cleanup(ctx)** - Cleans up resources

### Step 4: Convert Error Handling to Result[T] Pattern

The SDK uses a functional `Result[T]` pattern instead of `(T, error)` tuples:

```go
// Before - (T, error) pattern
func processData(input string) (string, error) {
    if input == "" {
        return "", errors.New("input cannot be empty")
    }

    result := strings.ToUpper(input)
    return result, nil
}

// After - Result[T] pattern
func processData(input string) models.Result[string] {
    if input == "" {
        return models.Err[string](fmt.Errorf("input cannot be empty"))
    }

    result := strings.ToUpper(input)
    return models.Ok(result)
}
```

#### Working with Results

```go
// Checking results
result := processData("hello")
if result.IsErr() {
    log.Printf("Error: %v", result.Error())
    return
}

value := result.Unwrap()
fmt.Printf("Result: %s", value)

// Chaining results
func processChain(input string) models.Result[string] {
    step1 := processData(input)
    if step1.IsErr() {
        return step1
    }

    // Continue processing
    processed := step1.Unwrap()
    return models.Ok(processed + " - processed")
}

// Using UnwrapOr for defaults
value := result.UnwrapOr("default value")
```

### Step 5: Update Type References

Update all type references to use SDK types:

```go
// Before
func createFinding(severity shared.Severity) *shared.Finding {
    return &shared.Finding{
        Severity: severity,
        Title:    "Security Issue",
    }
}

// After
func createFinding(severity plugin.Severity) models.Finding {
    return models.Finding{
        ID:       uuid.New(),
        Severity: severity,
        Title:    "Security Issue",
        CreatedAt: time.Now(),
    }
}
```

#### Type Mapping Reference

| Old Type | New Type |
|----------|----------|
| `shared.PluginInfo` | `models.PluginInfo` |
| `shared.Target` | `models.Target` |
| `shared.AssessRequest` | `models.AssessRequest` |
| `shared.AssessResponse` | `models.AssessResponse` |
| `shared.Finding` | `models.Finding` |
| `shared.Payload` | `models.Payload` |
| `shared.SecurityDomain` | `plugin.SecurityDomain` |
| `shared.PayloadCategory` | `plugin.PayloadCategory` |
| `shared.PayloadType` | `plugin.PayloadType` |
| `shared.Severity` | `plugin.Severity` |

### Step 6: Update Plugin Initialization

The SDK uses a different plugin initialization pattern:

```go
// Before
func main() {
    plugin := &MyPlugin{}
    shared.ServePlugin(plugin)
}

// After
import (
    "github.com/zero-day-ai/gibson-sdk/pkg/grpc"
    "github.com/hashicorp/go-plugin"
)

func main() {
    pluginImpl := &MyPlugin{}

    pluginMap := map[string]plugin.Plugin{
        "security": &grpc.SecurityPluginGRPC{Impl: pluginImpl},
    }

    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: grpc.HandshakeConfig,
        Plugins:         pluginMap,
        GRPCServer:      plugin.DefaultGRPCServer,
    })
}
```

### Step 7: Update Configuration and Metadata

#### Plugin Configuration

```go
// Before
type Config struct {
    APIKey   string `json:"api_key"`
    Endpoint string `json:"endpoint"`
}

// After - Enhanced with validation
type Config struct {
    APIKey   string `json:"api_key" validate:"required"`
    Endpoint string `json:"endpoint" validate:"required,url"`
    Timeout  string `json:"timeout" validate:"duration"`
}

func (p *MyPlugin) Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool] {
    // Validate configuration using SDK validation
    if err := validation.ValidateStruct(config); err != nil {
        return models.Err[bool](fmt.Errorf("invalid configuration: %w", err))
    }

    p.config = config
    return models.Ok(true)
}
```

#### Plugin Metadata

```go
// Enhanced plugin metadata
func (p *MyPlugin) GetInfo() models.Result[models.PluginInfo] {
    info := models.PluginInfo{
        Name:        "my-awesome-plugin",
        Version:     "2.0.0",
        Domain:      plugin.SecurityDomainInterface,
        Description: "Comprehensive security assessment plugin",
        Author:      "Security Team",
        License:     "MIT",
        Tags:        []string{"security", "assessment", "interface"},
        Capabilities: map[string]interface{}{
            "streaming":     true,
            "batch_mode":    true,
            "async_support": true,
        },
    }
    return models.Ok(info)
}
```

### Step 8: Add Testing

The SDK provides comprehensive testing utilities:

```go
// test_plugin_test.go
package main

import (
    "context"
    "testing"

    "github.com/zero-day-ai/gibson-sdk/pkg/testing"
)

func TestMyPlugin(t *testing.T) {
    // Use SDK test harness
    harness := testing.NewPluginTestHarness()
    plugin := &MyPlugin{}

    // Test plugin compliance
    result := harness.TestCompliance(plugin)
    if !result.Passed {
        t.Errorf("Plugin compliance test failed: %v", result.Errors)
    }

    // Test with fixtures
    fixtures := testing.NewTestFixtures()
    request := fixtures.ValidAssessRequest()

    // Test execution
    response := plugin.Execute(context.Background(), request)
    if response.IsErr() {
        t.Errorf("Plugin execution failed: %v", response.Error())
    }
}

func TestMyPluginPerformance(t *testing.T) {
    harness := testing.NewPluginTestHarness()
    plugin := &MyPlugin{}

    // Performance benchmarks
    result := harness.BenchmarkPlugin(plugin, testing.BenchmarkConfig{
        Duration:    30 * time.Second,
        Concurrency: 10,
        RequestSize: 1024,
    })

    if result.AverageLatency > 100*time.Millisecond {
        t.Errorf("Plugin too slow: %v", result.AverageLatency)
    }
}
```

## Common Migration Issues and Solutions

### Issue 1: Import Resolution Errors

**Problem**: Import path not found after migration

**Solution**:
1. Run `go mod tidy` to update dependencies
2. Check that SDK version is correct in go.mod
3. Verify import paths match the mapping table

```bash
# Clean module cache if needed
go clean -modcache
go mod download
```

### Issue 2: Type Conversion Errors

**Problem**: Type mismatch between old and new types

**Solution**: Use type conversion utilities or update to new type structure

```go
// Convert old payload to new format
func convertPayload(oldPayload *shared.Payload) models.Payload {
    return models.Payload{
        ID:          uuid.New(),
        Name:        oldPayload.Name,
        Content:     oldPayload.Content,
        Category:    plugin.PayloadCategory(oldPayload.Category),
        Type:        plugin.PayloadType(oldPayload.Type),
        Severity:    plugin.Severity(oldPayload.Severity),
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
}
```

### Issue 3: Error Handling Migration

**Problem**: Complex error handling doesn't map cleanly to Result[T]

**Solution**: Break down complex error handling into smaller, composable functions

```go
// Before - complex error handling
func complexOperation(input string) (*Result, error) {
    if input == "" {
        return nil, errors.New("empty input")
    }

    step1, err := processStep1(input)
    if err != nil {
        return nil, fmt.Errorf("step1 failed: %w", err)
    }

    step2, err := processStep2(step1)
    if err != nil {
        return nil, fmt.Errorf("step2 failed: %w", err)
    }

    return step2, nil
}

// After - composed Result[T] handling
func complexOperation(input string) models.Result[*Result] {
    if input == "" {
        return models.Err[*Result](fmt.Errorf("empty input"))
    }

    step1Result := processStep1(input)
    if step1Result.IsErr() {
        return models.Err[*Result](fmt.Errorf("step1 failed: %w", step1Result.Error()))
    }

    step2Result := processStep2(step1Result.Unwrap())
    if step2Result.IsErr() {
        return models.Err[*Result](fmt.Errorf("step2 failed: %w", step2Result.Error()))
    }

    return models.Ok(step2Result.Unwrap())
}

// Helper functions return Result[T]
func processStep1(input string) models.Result[string] {
    // Implementation
    return models.Ok(processed)
}

func processStep2(input string) models.Result[*Result] {
    // Implementation
    return models.Ok(result)
}
```

### Issue 4: Context Handling

**Problem**: New interface requires context.Context parameters

**Solution**: Add context handling throughout your plugin

```go
// Update all methods to accept and use context
func (p *MyPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    // Check for cancellation
    select {
    case <-ctx.Done():
        return models.Err[models.AssessResponse](ctx.Err())
    default:
    }

    // Pass context to sub-operations
    result := p.performAssessment(ctx, request)
    if result.IsErr() {
        return models.Err[models.AssessResponse](result.Error())
    }

    return models.Ok(result.Unwrap())
}

func (p *MyPlugin) performAssessment(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    // Use context for timeouts, cancellation, etc.
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    // Implementation
    return models.Ok(response)
}
```

### Issue 5: gRPC Integration

**Problem**: Plugin doesn't work with framework after migration

**Solution**: Ensure proper gRPC setup and handshake configuration

```go
// Verify handshake configuration matches framework
import "github.com/zero-day-ai/gibson-sdk/pkg/grpc"

func main() {
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig:  grpc.HandshakeConfig, // Use SDK handshake
        Plugins: map[string]plugin.Plugin{
            "security": &grpc.SecurityPluginGRPC{Impl: &MyPlugin{}},
        },
        GRPCServer: plugin.DefaultGRPCServer,
    })
}
```

## Migration Checklist

### Pre-Migration

- [ ] ✅ Backup your plugin code
- [ ] ✅ Review current plugin functionality
- [ ] ✅ Check SDK compatibility matrix
- [ ] ✅ Set up development environment with SDK

### Migration Steps

- [ ] ✅ Update go.mod dependencies
- [ ] ✅ Update import statements
- [ ] ✅ Convert to Result[T] error handling
- [ ] ✅ Update interface implementation
- [ ] ✅ Add context handling
- [ ] ✅ Update type references
- [ ] ✅ Update plugin initialization
- [ ] ✅ Add proper configuration validation

### Post-Migration Testing

- [ ] ✅ Run `go mod tidy` and `go build`
- [ ] ✅ Test plugin loading with framework
- [ ] ✅ Run SDK compliance tests
- [ ] ✅ Verify all plugin methods work
- [ ] ✅ Test error handling scenarios
- [ ] ✅ Perform integration testing
- [ ] ✅ Validate performance benchmarks

### Production Deployment

- [ ] ✅ Update CI/CD pipelines
- [ ] ✅ Update deployment scripts
- [ ] ✅ Monitor plugin performance
- [ ] ✅ Verify logging and metrics
- [ ] ✅ Test rollback procedures

## Advanced Migration Scenarios

### Migrating Streaming Plugins

For plugins that support streaming operations:

```go
// Implement StreamingPlugin interface
func (p *MyPlugin) ExecuteStream(ctx context.Context, request models.AssessRequest, resultChan chan<- models.StreamResult) models.Result[bool] {
    defer close(resultChan)

    // Send progress updates
    resultChan <- models.StreamResult{
        ID:        uuid.New(),
        Timestamp: time.Now(),
        Type:      "progress",
        Data: map[string]interface{}{
            "progress": 0.25,
            "message":  "Starting assessment",
        },
    }

    // Perform assessment with streaming results
    findings := p.performStreamingAssessment(ctx, request, resultChan)

    // Send final results
    for _, finding := range findings {
        select {
        case resultChan <- models.StreamResult{
            ID:        uuid.New(),
            Timestamp: time.Now(),
            Type:      "finding",
            Data:      map[string]interface{}{"finding": finding},
        }:
        case <-ctx.Done():
            return models.Err[bool](ctx.Err())
        }
    }

    return models.Ok(true)
}
```

### Migrating Batch Plugins

For plugins that support batch processing:

```go
// Implement BatchPlugin interface
func (p *MyPlugin) ExecuteBatch(ctx context.Context, requests []models.AssessRequest) models.Result[[]models.AssessResponse] {
    responses := make([]models.AssessResponse, len(requests))

    // Use worker pool for parallel processing
    type job struct {
        index   int
        request models.AssessRequest
    }

    jobs := make(chan job, len(requests))
    results := make(chan struct {
        index    int
        response models.AssessResponse
        err      error
    }, len(requests))

    // Start workers
    const numWorkers = 5
    for i := 0; i < numWorkers; i++ {
        go func() {
            for job := range jobs {
                response := p.Execute(ctx, job.request)
                if response.IsErr() {
                    results <- struct {
                        index    int
                        response models.AssessResponse
                        err      error
                    }{job.index, models.AssessResponse{}, response.Error()}
                } else {
                    results <- struct {
                        index    int
                        response models.AssessResponse
                        err      error
                    }{job.index, response.Unwrap(), nil}
                }
            }
        }()
    }

    // Send jobs
    for i, request := range requests {
        jobs <- job{i, request}
    }
    close(jobs)

    // Collect results
    for i := 0; i < len(requests); i++ {
        result := <-results
        if result.err != nil {
            return models.Err[[]models.AssessResponse](result.err)
        }
        responses[result.index] = result.response
    }

    return models.Ok(responses)
}
```

## Getting Help

### Documentation

- [SDK API Reference](./docs/API.md)
- [Compatibility Matrix](./COMPATIBILITY.md)
- [Example Plugins](./examples/)
- [Testing Guide](./docs/testing.md)

### Community Support

- [Gibson Discord](https://discord.gg/gibson-security)
- [GitHub Issues](https://github.com/zero-day-ai/gibson-sdk/issues)
- [Developer Forums](https://community.gibson-sec.com)

### Professional Support

For enterprise customers needing migration assistance:

- Email: support@gibson-sec.com
- Migration consulting services available
- Custom training and workshops

## Migration Tools

### Automated Migration Tool

```bash
# Install migration tool
go install github.com/zero-day-ai/gibson-sdk/cmd/migrate@latest

# Get help
gibson-migrate --help

# Common usage patterns
gibson-migrate --plugin-dir ./my-plugin --dry-run --verbose
gibson-migrate --plugin-dir ./plugins --recursive --backup
gibson-migrate --plugin-dir ./old-plugin --output-dir ./new-plugin
```

### Version Compatibility Checker

```bash
# Check compatibility
go run github.com/zero-day-ai/gibson-sdk/cmd/version-check \
  --sdk-version v1.0.0 \
  --framework-version v2.0.0
```

### Validation Tools

```bash
# Validate migrated plugin
go run github.com/zero-day-ai/gibson-sdk/cmd/validate \
  --plugin-dir ./migrated-plugin
```

---

**Last Updated**: 2024-01-15
**SDK Version**: v1.0.0
**Guide Version**: 1.0

This migration guide is a living document. Please [contribute improvements](https://github.com/zero-day-ai/gibson-sdk/blob/main/CONTRIBUTING.md) or [report issues](https://github.com/zero-day-ai/gibson-sdk/issues) to help other developers.