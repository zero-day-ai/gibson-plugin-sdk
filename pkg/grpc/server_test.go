package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-sdk/pkg/grpc/proto"
	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGRPCServer(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	assert.NotNil(t, server)
	assert.Equal(t, mockPlugin, server.plugin)
}

func TestGRPCServer_GetInfo(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()
	req := &proto.GetInfoRequest{}

	resp, err := server.GetInfo(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "test-plugin", resp.Name)
	assert.Equal(t, "1.0.0", resp.Version)
	assert.Equal(t, string(plugin.DomainInterface), resp.Domain)
	assert.True(t, resp.Success)
	assert.Empty(t, resp.Error)
}

func TestGRPCServer_GetInfo_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.infoResult = models.Err[*plugin.PluginInfo](assert.AnError)

	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.GetInfoRequest{}

	resp, err := server.GetInfo(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Success)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, assert.AnError.Error())
}

func TestGRPCServer_Execute(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()
	req := &proto.ExecuteRequest{
		RequestId: "test-request",
		Target: &proto.Target{
			Id:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &proto.AssessmentConfig{
			Domain:         string(plugin.DomainInterface),
			MaxFindings:    10,
			TimeoutSeconds: 30,
		},
	}

	resp, err := server.Execute(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)
	assert.True(t, resp.Completed)
	assert.Equal(t, "test-request", resp.RequestId)
	assert.Empty(t, resp.Error)
}

func TestGRPCServer_Execute_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.executeResult = models.Err[*plugin.AssessResponse](assert.AnError)

	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.ExecuteRequest{
		RequestId: "test-request",
		Target: &proto.Target{
			Id:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &proto.AssessmentConfig{
			Domain: string(plugin.DomainInterface),
		},
	}

	resp, err := server.Execute(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Success)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, assert.AnError.Error())
}

func TestGRPCServer_Execute_NilRequest(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()

	resp, err := server.Execute(ctx, nil)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestGRPCServer_Execute_NilTarget(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()
	req := &proto.ExecuteRequest{
		RequestId: "test-request",
		Target:    nil,
		Config: &proto.AssessmentConfig{
			Domain: string(plugin.DomainInterface),
		},
	}

	resp, err := server.Execute(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "target cannot be nil")
}

func TestGRPCServer_Execute_NilConfig(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()
	req := &proto.ExecuteRequest{
		RequestId: "test-request",
		Target: &proto.Target{
			Id:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: nil,
	}

	resp, err := server.Execute(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

func TestGRPCServer_Validate(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()
	req := &proto.ValidateRequest{
		Request: &proto.ExecuteRequest{
			RequestId: "test-request",
			Target: &proto.Target{
				Id:   "test-target",
				Name: "Test Target",
				Type: "api",
			},
			Config: &proto.AssessmentConfig{
				Domain: string(plugin.DomainInterface),
			},
		},
	}

	resp, err := server.Validate(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Valid)
	assert.Equal(t, "validation passed", resp.Message)
	assert.Empty(t, resp.Errors)
}

func TestGRPCServer_Validate_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.validateResult = models.Err[*plugin.ValidationResult](assert.AnError)

	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.ValidateRequest{
		Request: &proto.ExecuteRequest{
			RequestId: "test-request",
			Target: &proto.Target{
				Id:   "test-target",
				Name: "Test Target",
				Type: "api",
			},
			Config: &proto.AssessmentConfig{
				Domain: string(plugin.DomainInterface),
			},
		},
	}

	resp, err := server.Validate(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), assert.AnError.Error())
}

func TestGRPCServer_Validate_NilRequest(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()

	resp, err := server.Validate(ctx, nil)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestGRPCServer_Health(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)

	ctx := context.Background()
	req := &proto.HealthRequest{}

	resp, err := server.Health(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, string(plugin.HealthStatusHealthy), resp.Status)
	assert.Equal(t, "plugin is healthy", resp.Message)
	assert.NotZero(t, resp.Timestamp)
}

func TestGRPCServer_Health_Error(t *testing.T) {
	mockPlugin := NewMockGRPCPlugin()
	mockPlugin.healthResult = models.Err[*plugin.HealthStatus](assert.AnError)

	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.HealthRequest{}

	resp, err := server.Health(ctx, req)
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), assert.AnError.Error())
}

func TestGRPCServer_ConvertExecuteRequest(t *testing.T) {
	protoReq := &proto.ExecuteRequest{
		RequestId: "test-request",
		Target: &proto.Target{
			Id:       "test-target",
			Name:     "Test Target",
			Type:     "api",
			Endpoint: "https://api.example.com",
			Configuration: map[string]string{
				"timeout": "30s",
			},
			Tags: []string{"test", "api"},
			Metadata: map[string]string{
				"version": "1.0",
			},
		},
		Config: &proto.AssessmentConfig{
			Domain:              string(plugin.DomainInterface),
			PayloadTypes:        []string{string(plugin.PayloadTypeInput)},
			MaxFindings:         100,
			TimeoutSeconds:      60,
			EnableStreaming:     true,
			ConcurrentExecution: false,
			Options: map[string]string{
				"aggressive": "false",
			},
		},
		Context: map[string]string{
			"user": "test-user",
		},
	}

	pluginReq := convertExecuteRequest(protoReq)

	assert.Equal(t, "test-request", pluginReq.RequestID)
	assert.Equal(t, "test-target", pluginReq.Target.ID)
	assert.Equal(t, "Test Target", pluginReq.Target.Name)
	assert.Equal(t, "api", pluginReq.Target.Type)
	assert.Equal(t, "https://api.example.com", pluginReq.Target.Endpoint)
	assert.Equal(t, "30s", pluginReq.Target.Configuration["timeout"])
	assert.Contains(t, pluginReq.Target.Tags, "test")
	assert.Contains(t, pluginReq.Target.Tags, "api")
	assert.Equal(t, "1.0", pluginReq.Target.Metadata["version"])

	assert.Equal(t, plugin.DomainInterface, pluginReq.Config.Domain)
	assert.Contains(t, pluginReq.Config.PayloadTypes, plugin.PayloadTypeInput)
	assert.Equal(t, 100, pluginReq.Config.MaxFindings)
	assert.Equal(t, 60, pluginReq.Config.TimeoutSeconds)
	assert.True(t, pluginReq.Config.EnableStreaming)
	assert.False(t, pluginReq.Config.ConcurrentExecution)
	assert.Equal(t, "false", pluginReq.Config.Options["aggressive"].(string))

	assert.Equal(t, "test-user", pluginReq.Context["user"])
}

func TestGRPCServer_ConvertAssessResponse(t *testing.T) {
	now := time.Now()
	pluginResp := &plugin.AssessResponse{
		Success:   true,
		Error:     "",
		Completed: true,
		Findings: []*plugin.Finding{
			{
				ID:          "finding-1",
				Title:       "Test Finding",
				Description: "Test description",
				Severity:    plugin.SeverityHigh,
				Domain:      plugin.DomainInterface,
				PayloadType: plugin.PayloadTypeInput,
				Payload:     "test payload",
				Location:    "/api/test",
				Tags:        []string{"sql", "injection"},
				Metadata: map[string]string{
					"confidence": "high",
				},
				DiscoveredAt: now,
			},
		},
		StartTime: now.Add(-time.Minute),
		EndTime:   now,
		Duration:  time.Minute,
		Metadata: map[string]string{
			"version": "1.0.0",
		},
		ResourceUsage: &plugin.ResourceUsage{
			CPUTime:    time.Second,
			Memory:     1024 * 1024,
			NetworkIn:  512,
			NetworkOut: 256,
			APICalls:   10,
			MaxMemory:  2 * 1024 * 1024,
			Goroutines: 5,
		},
		RequestID: "test-request",
	}

	protoResp := convertAssessResponse(pluginResp)

	assert.True(t, protoResp.Success)
	assert.Empty(t, protoResp.Error)
	assert.True(t, protoResp.Completed)
	assert.Len(t, protoResp.Findings, 1)

	finding := protoResp.Findings[0]
	assert.Equal(t, "finding-1", finding.Id)
	assert.Equal(t, "Test Finding", finding.Title)
	assert.Equal(t, "Test description", finding.Description)
	assert.Equal(t, string(plugin.SeverityHigh), finding.Severity)
	assert.Equal(t, string(plugin.DomainInterface), finding.Domain)
	assert.Equal(t, string(plugin.PayloadTypeInput), finding.PayloadType)
	assert.Equal(t, "test payload", finding.Payload)
	assert.Equal(t, "/api/test", finding.Location)
	assert.Contains(t, finding.Tags, "sql")
	assert.Contains(t, finding.Tags, "injection")
	assert.Equal(t, "high", finding.Metadata["confidence"])
	assert.Equal(t, now.Unix(), finding.DiscoveredAt)

	assert.Equal(t, pluginResp.StartTime.Unix(), protoResp.StartTime)
	assert.Equal(t, pluginResp.EndTime.Unix(), protoResp.EndTime)
	assert.Equal(t, int64(time.Minute), protoResp.Duration)
	assert.Equal(t, "1.0.0", protoResp.Metadata["version"])

	assert.NotNil(t, protoResp.ResourceUsage)
	assert.Equal(t, int64(time.Second), protoResp.ResourceUsage.CpuTime)
	assert.Equal(t, int64(1024*1024), protoResp.ResourceUsage.Memory)
	assert.Equal(t, int64(512), protoResp.ResourceUsage.NetworkIn)
	assert.Equal(t, int64(256), protoResp.ResourceUsage.NetworkOut)
	assert.Equal(t, int32(10), protoResp.ResourceUsage.ApiCalls)
	assert.Equal(t, int64(2*1024*1024), protoResp.ResourceUsage.MaxMemory)
	assert.Equal(t, int32(5), protoResp.ResourceUsage.Goroutines)

	assert.Equal(t, "test-request", protoResp.RequestId)
}

func TestGRPCServer_ConvertPluginInfo(t *testing.T) {
	now := time.Now()
	pluginInfo := &plugin.PluginInfo{
		Name:        "test-plugin",
		Version:     "1.0.0",
		Description: "Test plugin description",
		Author:      "Test Author",
		Domain:      plugin.DomainInterface,
		SupportedPayloadTypes: []plugin.PayloadType{
			plugin.PayloadTypeInput,
			plugin.PayloadTypeQuery,
		},
		Capabilities: &plugin.PluginCapabilities{
			SupportsStreaming:     true,
			SupportsBatch:         false,
			SupportsConcurrent:    true,
			MaxConcurrentRequests: 10,
			TimeoutSeconds:        30,
			RequiredPermissions:   []string{"read", "write"},
		},
		Metadata: map[string]string{
			"category": "security",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	protoInfo := convertPluginInfo(pluginInfo)

	assert.Equal(t, "test-plugin", protoInfo.Name)
	assert.Equal(t, "1.0.0", protoInfo.Version)
	assert.Equal(t, "Test plugin description", protoInfo.Description)
	assert.Equal(t, "Test Author", protoInfo.Author)
	assert.Equal(t, string(plugin.DomainInterface), protoInfo.Domain)
	assert.Contains(t, protoInfo.SupportedPayloadTypes, string(plugin.PayloadTypeInput))
	assert.Contains(t, protoInfo.SupportedPayloadTypes, string(plugin.PayloadTypeQuery))

	assert.NotNil(t, protoInfo.Capabilities)
	assert.True(t, protoInfo.Capabilities.SupportsStreaming)
	assert.False(t, protoInfo.Capabilities.SupportsBatch)
	assert.True(t, protoInfo.Capabilities.SupportsConcurrent)
	assert.Equal(t, int32(10), protoInfo.Capabilities.MaxConcurrentRequests)
	assert.Equal(t, int32(30), protoInfo.Capabilities.TimeoutSeconds)
	assert.Contains(t, protoInfo.Capabilities.RequiredPermissions, "read")
	assert.Contains(t, protoInfo.Capabilities.RequiredPermissions, "write")

	assert.Equal(t, "security", protoInfo.Metadata["category"])
	assert.Equal(t, now.Unix(), protoInfo.CreatedAt)
	assert.Equal(t, now.Unix(), protoInfo.UpdatedAt)
}

// Benchmark tests
func BenchmarkGRPCServer_GetInfo(b *testing.B) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.GetInfoRequest{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := server.GetInfo(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		if !resp.Success {
			b.Fatal("GetInfo failed")
		}
	}
}

func BenchmarkGRPCServer_Execute(b *testing.B) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.ExecuteRequest{
		RequestId: "test-request",
		Target: &proto.Target{
			Id:   "test-target",
			Name: "Test Target",
			Type: "api",
		},
		Config: &proto.AssessmentConfig{
			Domain: string(plugin.DomainInterface),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := server.Execute(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		if !resp.Success {
			b.Fatal("Execute failed")
		}
	}
}

func BenchmarkGRPCServer_Health(b *testing.B) {
	mockPlugin := NewMockGRPCPlugin()
	server := NewGRPCServer(mockPlugin)
	ctx := context.Background()
	req := &proto.HealthRequest{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := server.Health(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		if resp.Status != string(plugin.HealthStatusHealthy) {
			b.Fatal("Health check failed")
		}
	}
}
