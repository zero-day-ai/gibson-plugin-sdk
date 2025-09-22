# Gibson Plugin SDK

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/zero-day-ai/gibson-sdk)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)](https://github.com/zero-day-ai/gibson-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/zero-day-ai/gibson-sdk)](https://goreportcard.com/report/github.com/zero-day-ai/gibson-sdk)

The Gibson Plugin SDK is a comprehensive Go framework for building security assessment plugins for the Gibson Framework. It provides a robust, type-safe, and extensible foundation for developing plugins that can assess AI/ML systems, web applications, APIs, and other digital assets.

## Features

- **🔧 Type-Safe Architecture**: Built with Go generics and functional error handling using Result[T] patterns
- **🔌 Process Isolation**: gRPC-based plugin communication with HashiCorp go-plugin
- **🎯 Domain-Driven Design**: Support for six security domains (Model, Data, Interface, Infrastructure, Output, Process)
- **📊 Comprehensive Testing**: Built-in test harness, mock implementations, and performance benchmarking
- **⚡ High Performance**: Optimized for low-latency, high-throughput security assessments
- **🛡️ Security First**: Input validation, secure credential handling, and audit trails
- **📚 Rich Documentation**: Complete API reference, guides, and examples

## Quick Start

### Installation

```bash
go get github.com/zero-day-ai/gibson-sdk@latest
```

### Create Your First Plugin

```go
package main

import (
    "context"
    "time"

    "github.com/zero-day-ai/gibson-sdk/pkg/plugin"
    "github.com/zero-day-ai/gibson-sdk/pkg/core/models"
    "github.com/zero-day-ai/gibson-sdk/pkg/grpc"
    "github.com/hashicorp/go-plugin"
    "github.com/google/uuid"
)

type MySecurityPlugin struct {
    plugin.BasePlugin
}

func (p *MySecurityPlugin) GetInfo() models.Result[models.PluginInfo] {
    info := models.PluginInfo{
        Name:        "my-security-plugin",
        Version:     "1.0.0",
        Domain:      plugin.SecurityDomainInterface,
        Description: "Example security assessment plugin",
        Author:      "Your Name",
        License:     "MIT",
        Tags:        []string{"security", "assessment"},
    }
    return models.Ok(info)
}

func (p *MySecurityPlugin) Initialize(ctx context.Context, config map[string]interface{}) models.Result[bool] {
    // Plugin initialization logic
    return models.Ok(true)
}

func (p *MySecurityPlugin) Validate(ctx context.Context, request models.AssessRequest) models.Result[bool] {
    // Validate the assessment request
    if request.Target.URL == "" {
        return models.Err[bool](fmt.Errorf("target URL is required"))
    }
    return models.Ok(true)
}

func (p *MySecurityPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
    // Perform security assessment
    response := models.AssessResponse{
        ID:         uuid.New(),
        PluginName: "my-security-plugin",
        Status:     "completed",
        StartTime:  time.Now(),
        EndTime:    time.Now(),
        Findings:   []models.Finding{}, // Add your findings here
        Metadata:   map[string]interface{}{
            "assessed_url": request.Target.URL,
        },
    }

    return models.Ok(response)
}

func (p *MySecurityPlugin) Cleanup(ctx context.Context) models.Result[bool] {
    // Cleanup resources
    return models.Ok(true)
}

func main() {
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: grpc.HandshakeConfig,
        Plugins: map[string]plugin.Plugin{
            "security": &grpc.SecurityPluginGRPC{Impl: &MySecurityPlugin{}},
        },
        GRPCServer: plugin.DefaultGRPCServer,
    })
}
```

## Documentation

- **[Getting Started Guide](docs/getting-started/README.md)**
- **[API Reference](docs/API.md)**
- **[Migration Guide](MIGRATION.md)**
- **[Compatibility Matrix](COMPATIBILITY.md)**

## Examples

- **[Minimal Plugin](examples/minimal/)**
- **[SQL Injection Detector](examples/sql-injection/)**
- **[Prompt Injection Detector](examples/prompt-injection/)**

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.