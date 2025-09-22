package main

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/grpc"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
)

// MinimalPlugin is a simple example plugin that demonstrates the basic SDK usage
type MinimalPlugin struct {
	*plugin.BasePlugin
}

// NewMinimalPlugin creates a new minimal plugin instance
func NewMinimalPlugin() *MinimalPlugin {
	info := &plugin.PluginInfo{
		Name:        "minimal-example",
		Version:     "1.0.0",
		Description: "A minimal example plugin for Gibson Framework",
		Author:      "Gibson SDK Team",
		Domain:      plugin.DomainInterface,
		SupportedPayloadTypes: []plugin.PayloadType{
			plugin.PayloadTypePrompt,
			plugin.PayloadTypeInput,
		},
		Capabilities: &plugin.PluginCapabilities{
			SupportsStreaming:     false,
			SupportsBatch:         false,
			SupportsConcurrent:    false,
			MaxConcurrentRequests: 1,
			TimeoutSeconds:        30,
			RequiredPermissions:   []string{},
		},
		Metadata: map[string]string{
			"category": "example",
			"tags":     "minimal,demo",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return &MinimalPlugin{
		BasePlugin: plugin.NewBasePlugin(info),
	}
}

// Execute performs a minimal security assessment
func (p *MinimalPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
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

	// Simulate some processing time
	time.Sleep(100 * time.Millisecond)

	// Create a basic finding for demonstration
	finding := &plugin.Finding{
		ID:          "MINIMAL-001",
		Title:       "Example Finding",
		Description: "This is a demonstration finding created by the minimal example plugin",
		Severity:    plugin.SeverityInfo,
		Domain:      plugin.DomainInterface,
		PayloadType: plugin.PayloadTypeInput,
		Payload:     "example test input",
		Location:    request.Target.Endpoint,
		Evidence: &plugin.Evidence{
			Type: "demonstration",
			Data: "This is example evidence data",
			Context: map[string]string{
				"target_type": request.Target.Type,
				"plugin":      "minimal-example",
			},
		},
		Remediation: &plugin.Remediation{
			Description: "This is an example finding for demonstration purposes",
			Steps: []string{
				"Review the target configuration",
				"Apply appropriate security measures",
				"Test the implementation",
			},
			Priority:   "low",
			Effort:     "minimal",
			References: []string{"https://example.com/security-guide"},
		},
		Tags:         []string{"example", "demo"},
		Metadata:     map[string]string{"source": "minimal-plugin"},
		DiscoveredAt: time.Now(),
	}

	endTime := time.Now()

	response := &plugin.AssessResponse{
		Success:   true,
		Completed: true,
		Findings:  []*plugin.Finding{finding},
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
		RequestID: request.RequestID,
		Metadata: map[string]string{
			"findings_count": "1",
			"execution_time": endTime.Sub(startTime).String(),
			"plugin_version": "1.0.0",
		},
	}

	return models.Ok(response)
}

func main() {
	// Create the plugin instance
	plugin := NewMinimalPlugin()

	// Serve the plugin using the Gibson SDK
	grpc.Serve(plugin)
}
