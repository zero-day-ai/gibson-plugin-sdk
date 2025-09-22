// Package plugin defines the interfaces and types for Gibson Framework security plugins
package plugin

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
)

// SecurityPlugin is the core interface that all Gibson security plugins must implement.
// This interface uses the Result[T] pattern for consistent error handling across all operations.
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

// StreamingPlugin extends SecurityPlugin to support streaming assessments
// This is useful for long-running assessments that produce results incrementally
type StreamingPlugin interface {
	SecurityPlugin

	// ExecuteStreaming performs a security assessment with streaming results
	ExecuteStreaming(ctx context.Context, request *AssessRequest, resultChan chan<- models.Result[*Finding]) models.Result[*AssessResponse]

	// SupportsStreaming returns true if the plugin supports streaming execution
	SupportsStreaming() bool
}

// BatchPlugin extends SecurityPlugin to support batch processing of multiple targets
// This is useful for plugins that can optimize processing multiple targets together
type BatchPlugin interface {
	SecurityPlugin

	// ExecuteBatch performs security assessments on multiple targets
	ExecuteBatch(ctx context.Context, requests []*AssessRequest) models.Result[*BatchAssessResponse]

	// GetOptimalBatchSize returns the recommended batch size for this plugin
	GetOptimalBatchSize() int

	// SupportsBatch returns true if the plugin supports batch execution
	SupportsBatch() bool
}

// ConfigurablePlugin extends SecurityPlugin to support dynamic configuration
type ConfigurablePlugin interface {
	SecurityPlugin

	// GetConfigSchema returns the configuration schema for this plugin
	GetConfigSchema(ctx context.Context) models.Result[*ConfigSchema]

	// UpdateConfig updates the plugin configuration
	UpdateConfig(ctx context.Context, config map[string]interface{}) models.Result[bool]

	// GetCurrentConfig returns the current plugin configuration
	GetCurrentConfig(ctx context.Context) models.Result[map[string]interface{}]
}

// BasePlugin provides a default implementation that can be embedded in plugin implementations
// This provides sensible defaults and reduces boilerplate for plugin developers
type BasePlugin struct {
	info   *PluginInfo
	config map[string]interface{}
}

// NewBasePlugin creates a new BasePlugin with the given info
func NewBasePlugin(info *PluginInfo) *BasePlugin {
	return &BasePlugin{
		info:   info,
		config: make(map[string]interface{}),
	}
}

// GetInfo returns the plugin info
func (p *BasePlugin) GetInfo(ctx context.Context) models.Result[*PluginInfo] {
	if p.info == nil {
		return models.Err[*PluginInfo](ErrPluginNotInitialized)
	}
	return models.Ok(p.info)
}

// Health returns a successful health check by default
func (p *BasePlugin) Health(ctx context.Context) models.Result[*HealthStatus] {
	return models.Ok(&HealthStatus{
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
		Message:   "Plugin is healthy",
	})
}

// Validate performs basic validation of the request
func (p *BasePlugin) Validate(ctx context.Context, request *AssessRequest) models.Result[*ValidationResult] {
	if request == nil {
		return models.Ok(&ValidationResult{
			Valid:   false,
			Message: "request cannot be nil",
		})
	}

	if request.Target == nil {
		return models.Ok(&ValidationResult{
			Valid:   false,
			Message: "target cannot be nil",
		})
	}

	if request.Target.Name == "" {
		return models.Ok(&ValidationResult{
			Valid:   false,
			Message: "target name cannot be empty",
		})
	}

	return models.Ok(&ValidationResult{
		Valid:   true,
		Message: "request is valid",
	})
}

// GetCurrentConfig returns the current configuration
func (p *BasePlugin) GetCurrentConfig(ctx context.Context) models.Result[map[string]interface{}] {
	return models.Ok(p.config)
}

// UpdateConfig updates the plugin configuration
func (p *BasePlugin) UpdateConfig(ctx context.Context, config map[string]interface{}) models.Result[bool] {
	if config == nil {
		return models.Err[bool](ErrInvalidConfig)
	}
	p.config = config
	return models.Ok(true)
}

// HealthChecker interface for plugins that support custom health checks
type HealthChecker interface {
	HealthCheck(ctx context.Context) models.Result[*HealthResult]
}
