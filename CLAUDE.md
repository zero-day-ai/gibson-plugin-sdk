# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Core Development Tasks

**Build plugin examples:**
```bash
go build -o build/plugin examples/minimal/main.go
go build -o build/sql-injection examples/sql-injection/main.go
go build -o build/prompt-injection examples/prompt-injection/main.go
```

**Run tests:**
```bash
# Unit tests only
make test-unit
# or directly
go test -race -v ./pkg/...

# Run a single test
go test -v -run TestSecurityPlugin ./pkg/plugin/

# Quick development tests (short mode)
make test-short

# Full test suite with integration and e2e
make test

# Generate coverage report
make test-coverage
```

**Linting and formatting:**
```bash
# Run all linters
make lint

# Auto-fix linting issues
make lint-fix

# Format code
make fmt

# Security scan
make security

# Run complete CI checks (lint, test, security)
make ci

# Quick development cycle (fmt, vet, short tests)
make dev
```

**Dependency management:**
```bash
# Check and clean dependencies
make deps-check

# Update dependencies
go get -u ./...
go mod tidy
```

## Architecture Overview

### Plugin Interface Pattern
The SDK uses a **Result[T] functional error handling pattern** throughout:

```go
// Success returns: models.Ok(value)
// Error returns: models.Err[T](error)
// Check with: result.IsOk() or result.IsErr()
// Extract with: result.Unwrap() or result.UnwrapErr()
```

### Core Plugin Methods
Every plugin must implement the `SecurityPlugin` interface:
- `GetInfo(ctx) Result[*PluginInfo]` - Return plugin metadata
- `Execute(ctx, *AssessRequest) Result[*AssessResponse]` - Perform assessment
- `Validate(ctx, *AssessRequest) Result[*ValidationResult]` - Validate request
- `Health(ctx) Result[*HealthStatus]` - Health check

### Package Structure

**Core packages:**
- `pkg/plugin/` - Plugin interfaces (`SecurityPlugin`, `StreamingPlugin`, `BatchPlugin`)
- `pkg/plugin/types.go` - Core types (`PluginInfo`, `AssessRequest`, `Finding`, etc.)
- `pkg/plugin/domains.go` - Security domains (`SecurityDomainModel`, `SecurityDomainInterface`, etc.)
- `pkg/plugin/errors.go` - Standard errors

**Supporting packages:**
- `pkg/core/models/` - Result[T] pattern implementation
- `pkg/grpc/` - gRPC server and protobuf handling
- `pkg/testing/` - Test harness and fixtures
- `pkg/validation/` - Input validation utilities

### gRPC Architecture
Plugins communicate via gRPC using HashiCorp's go-plugin:
- Server implementation in `pkg/grpc/server.go`
- Proto definitions in `pkg/grpc/proto/`
- Health checking via standard gRPC health protocol
- Support for streaming and batch operations

## Key Types and Enums

**Security Domains:**
- `SecurityDomainModel` - AI/ML model security
- `SecurityDomainData` - Data security and privacy
- `SecurityDomainInterface` - User interface security
- `SecurityDomainInfrastructure` - System/infra security
- `SecurityDomainOutput` - Output validation
- `SecurityDomainProcess` - Process and governance

**Severity Levels:**
- `SeverityCritical`, `SeverityHigh`, `SeverityMedium`, `SeverityLow`, `SeverityInfo`

**Payload Types:**
- `PayloadTypePrompt`, `PayloadTypeQuery`, `PayloadTypeInput`, `PayloadTypeCode`, `PayloadTypeData`, `PayloadTypeScript`

## Plugin Implementation Pattern

```go
type MyPlugin struct {
    plugin.BasePlugin  // Embed for default implementations
}

func (p *MyPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
    // 1. Validate request
    if request.Target == nil {
        return models.Err[*plugin.AssessResponse](fmt.Errorf("target required"))
    }

    // 2. Perform assessment
    findings := p.performAssessment(ctx, request.Target)

    // 3. Return response
    return models.Ok(&plugin.AssessResponse{
        Success:   true,
        Findings:  findings,
        StartTime: startTime,
        EndTime:   time.Now(),
    })
}
```

## Testing Pattern

Use the provided test harness:
```go
harness := testing.NewPluginTestHarness()
result := harness.TestCompliance(myPlugin)

fixtures := testing.NewTestFixtures()
request := fixtures.ValidAssessRequest()
```

## Common Gotchas

1. **Always use Result[T] pattern** - Don't return bare errors
2. **Context handling** - Always check `ctx.Done()` for cancellation
3. **Plugin serving** - Must use `plugin.Serve()` with proper HandshakeConfig
4. **Finding IDs** - Use `github.com/google/uuid` for generating IDs
5. **Timeout handling** - Respect `Config.TimeoutSeconds` in AssessmentConfig