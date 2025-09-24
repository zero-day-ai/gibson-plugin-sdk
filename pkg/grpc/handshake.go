package grpc

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/grpc/proto"
	pluginpkg "github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
)

// ProtocolVersion defines the protocol version for Gibson plugins
const ProtocolVersion = 1

// MagicCookieKey is the key for the magic cookie
const MagicCookieKey = "GIBSON_PLUGIN"

// MagicCookieValue is the value for the magic cookie
// This should be a secure random value that prevents unauthorized plugins
const MagicCookieValue = "gibson-security-plugin-v1-2024"

// HandshakeConfig defines the handshake configuration for Gibson plugins
var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   MagicCookieKey,
	MagicCookieValue: MagicCookieValue,
}

// PluginMap defines the plugin map for Gibson security plugins
var PluginMap = map[string]plugin.Plugin{
	"security": &GibsonSecurityPlugin{},
}

// GibsonSecurityPlugin implements the HashiCorp plugin interface for Gibson security plugins
type GibsonSecurityPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	Impl pluginpkg.SecurityPlugin
}

// GRPCServer registers the plugin as a gRPC server
func (p *GibsonSecurityPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	if p.Impl == nil {
		return fmt.Errorf("plugin implementation not set")
	}

	// Get plugin info
	ctx := context.Background()
	infoResult := p.Impl.GetInfo(ctx)
	if infoResult.IsErr() {
		return fmt.Errorf("failed to get plugin info: %w", infoResult.Error())
	}

	info := infoResult.Unwrap()

	// Create plugin server
	pluginServer := NewPluginServer(p.Impl, info)

	// Register the service
	proto.RegisterPluginServiceServer(s, pluginServer)

	return nil
}

// GRPCClient creates a gRPC client for the plugin
func (p *GibsonSecurityPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	// Create the gRPC client
	client := &GibsonSecurityPluginClient{
		client: proto.NewPluginServiceClient(c),
		conn:   c,
	}

	return client, nil
}

// GibsonSecurityPluginClient wraps the gRPC client to implement the SecurityPlugin interface
type GibsonSecurityPluginClient struct {
	client proto.PluginServiceClient
	conn   *grpc.ClientConn
}

// GetInfo implements SecurityPlugin.GetInfo
func (c *GibsonSecurityPluginClient) GetInfo(ctx context.Context) models.Result[*pluginpkg.PluginInfo] {
	resp, err := c.client.GetInfo(ctx, &proto.GetInfoRequest{})
	if err != nil {
		return models.Err[*pluginpkg.PluginInfo](fmt.Errorf("GetInfo failed: %w", err))
	}

	info := convertProtoPluginInfo(resp.Info)
	return models.Ok(info)
}

// Execute implements SecurityPlugin.Execute
func (c *GibsonSecurityPluginClient) Execute(ctx context.Context, request *pluginpkg.AssessRequest) models.Result[*pluginpkg.AssessResponse] {
	// Convert request to proto
	protoReq := &proto.AssessRequest{
		RequestId: request.RequestID,
		Target:    convertTargetToProto(request.Target),
		Config:    convertAssessmentConfigToProto(request.Config),
		Context:   request.Context,
		Timestamp: timestampNow(),
	}

	resp, err := c.client.Assess(ctx, protoReq)
	if err != nil {
		return models.Err[*pluginpkg.AssessResponse](fmt.Errorf("Execute failed: %w", err))
	}

	if !resp.Success {
		return models.Err[*pluginpkg.AssessResponse](fmt.Errorf("plugin execution failed: %s", resp.ErrorMessage))
	}

	// Convert proto response to plugin response
	assessResponse := &pluginpkg.AssessResponse{
		Success:   resp.Success,
		Error:     resp.ErrorMessage,
		Completed: true,
		RequestID: resp.RequestId,
		ScanID:    "", // Not available in proto response
	}

	// Convert findings
	for _, protoFinding := range resp.Findings {
		finding := convertProtoFinding(protoFinding)
		if finding != nil {
			assessResponse.Findings = append(assessResponse.Findings, finding)
		}
	}

	// Convert metadata
	if resp.Metadata != nil {
		assessResponse.StartTime = timeFromTimestamp(resp.Metadata.StartedAt)
		assessResponse.EndTime = timeFromTimestamp(resp.Metadata.CompletedAt)
		assessResponse.Duration = timeFromTimestamp(resp.Metadata.CompletedAt).Sub(timeFromTimestamp(resp.Metadata.StartedAt))
		assessResponse.Metadata = make(map[string]string)
		for k, v := range resp.Metadata.PerformanceMetrics {
			assessResponse.Metadata[k] = v
		}
	}

	return models.Ok(assessResponse)
}

// Validate implements SecurityPlugin.Validate
func (c *GibsonSecurityPluginClient) Validate(ctx context.Context, request *pluginpkg.AssessRequest) models.Result[*pluginpkg.ValidationResult] {
	// For now, perform basic validation on the client side
	if request == nil {
		return models.Ok(&pluginpkg.ValidationResult{
			Valid:   false,
			Message: "request cannot be nil",
		})
	}

	if request.Target == nil {
		return models.Ok(&pluginpkg.ValidationResult{
			Valid:   false,
			Message: "target cannot be nil",
		})
	}

	if request.Target.Name == "" {
		return models.Ok(&pluginpkg.ValidationResult{
			Valid:   false,
			Message: "target name cannot be empty",
		})
	}

	return models.Ok(&pluginpkg.ValidationResult{
		Valid:   true,
		Message: "request is valid",
	})
}

// Health implements SecurityPlugin.Health
func (c *GibsonSecurityPluginClient) Health(ctx context.Context) models.Result[*pluginpkg.HealthStatus] {
	resp, err := c.client.HealthCheck(ctx, &proto.HealthCheckRequest{})
	if err != nil {
		return models.Err[*pluginpkg.HealthStatus](fmt.Errorf("health check failed: %w", err))
	}

	var status pluginpkg.HealthStatusType
	switch resp.Status {
	case proto.HealthStatus_HEALTH_STATUS_SERVING:
		status = pluginpkg.HealthStatusHealthy
	case proto.HealthStatus_HEALTH_STATUS_NOT_SERVING:
		status = pluginpkg.HealthStatusUnhealthy
	default:
		status = pluginpkg.HealthStatusUnknown
	}

	healthStatus := &pluginpkg.HealthStatus{
		Status:    status,
		Message:   resp.Message,
		Timestamp: timeFromTimestamp(timestampNow()),
		Details:   make(map[string]interface{}),
	}

	// Convert details
	for k, v := range resp.Details {
		healthStatus.Details[k] = v
	}

	return models.Ok(healthStatus)
}

// PluginConfig contains configuration for running a plugin
type PluginConfig struct {
	PluginPath       string            `json:"plugin_path"`       // Path to the plugin executable
	PluginArgs       []string          `json:"plugin_args"`       // Arguments to pass to the plugin
	Environment      map[string]string `json:"environment"`       // Environment variables
	LogLevel         string            `json:"log_level"`         // Log level for the plugin
	HandshakeTimeout int               `json:"handshake_timeout"` // Handshake timeout in seconds
	StartupTimeout   int               `json:"startup_timeout"`   // Startup timeout in seconds
}

// DefaultPluginConfig returns default plugin configuration
func DefaultPluginConfig() *PluginConfig {
	return &PluginConfig{
		LogLevel:         "INFO",
		HandshakeTimeout: 30,
		StartupTimeout:   60,
		Environment:      make(map[string]string),
		PluginArgs:       []string{},
	}
}

// HashiCorpPluginClient manages the lifecycle of a plugin process using HashiCorp go-plugin
type HashiCorpPluginClient struct {
	config *PluginConfig
	client *plugin.Client
	plugin pluginpkg.SecurityPlugin
}

// NewHashiCorpPluginClient creates a new HashiCorp plugin client with the given configuration
func NewHashiCorpPluginClient(config *PluginConfig) *HashiCorpPluginClient {
	if config == nil {
		config = DefaultPluginConfig()
	}

	return &HashiCorpPluginClient{
		config: config,
	}
}

// Start starts the plugin process and establishes connection
func (pc *HashiCorpPluginClient) Start() error {
	if pc.client != nil {
		return fmt.Errorf("plugin already started")
	}

	// Verify plugin executable exists
	if _, err := os.Stat(pc.config.PluginPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin executable not found: %s", pc.config.PluginPath)
	}

	// Create the command to execute the plugin
	cmd := exec.Command(pc.config.PluginPath, pc.config.PluginArgs...)

	// Set environment variables
	env := os.Environ()
	for k, v := range pc.config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	// Create the client configuration
	clientConfig := &plugin.ClientConfig{
		HandshakeConfig:  HandshakeConfig,
		Plugins:          PluginMap,
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Logger:           nil, // Use default logger
	}

	// Start the plugin
	pc.client = plugin.NewClient(clientConfig)

	// Connect via RPC
	rpcClient, err := pc.client.Client()
	if err != nil {
		pc.client.Kill()
		pc.client = nil
		return fmt.Errorf("failed to connect to plugin: %w", err)
	}

	// Request the plugin
	pluginInterface, err := rpcClient.Dispense("security")
	if err != nil {
		pc.client.Kill()
		pc.client = nil
		return fmt.Errorf("failed to dispense plugin: %w", err)
	}

	// Cast to our interface
	securityPlugin, ok := pluginInterface.(pluginpkg.SecurityPlugin)
	if !ok {
		pc.client.Kill()
		pc.client = nil
		return fmt.Errorf("plugin does not implement SecurityPlugin interface")
	}

	pc.plugin = securityPlugin
	return nil
}

// Stop stops the plugin process
func (pc *HashiCorpPluginClient) Stop() {
	if pc.client != nil {
		pc.client.Kill()
		pc.client = nil
	}
	pc.plugin = nil
}

// Plugin returns the plugin interface
func (pc *HashiCorpPluginClient) Plugin() pluginpkg.SecurityPlugin {
	return pc.plugin
}

// IsRunning returns true if the plugin is running
func (pc *HashiCorpPluginClient) IsRunning() bool {
	return pc.client != nil && !pc.client.Exited()
}

// Serve serves the plugin as a HashiCorp plugin
// This should be called from the plugin's main function
func Serve(impl pluginpkg.SecurityPlugin) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"security": &GibsonSecurityPlugin{Impl: impl},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// ServeConfig contains configuration for serving a plugin
type ServeConfig struct {
	Implementation pluginpkg.SecurityPlugin
	LogLevel       string
}

// ServeWithConfig serves the plugin with custom configuration
func ServeWithConfig(config *ServeConfig) {
	if config == nil {
		panic("ServeConfig cannot be nil")
	}

	if config.Implementation == nil {
		panic("Implementation cannot be nil")
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"security": &GibsonSecurityPlugin{Impl: config.Implementation},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
