package grpc

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/core/models"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/grpc/proto"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
)

// PluginClient wraps a gRPC client for communicating with plugins
type PluginClient struct {
	conn      *grpc.ClientConn
	client    proto.PluginServiceClient
	address   string
	timeout   time.Duration
	connected bool
}

// ClientOptions configures the plugin client
type ClientOptions struct {
	Address        string
	Timeout        time.Duration
	MaxMessageSize int
	KeepaliveTime  time.Duration
}

// DefaultClientOptions returns default client options
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		Timeout:        30 * time.Second,
		MaxMessageSize: 1024 * 1024 * 16, // 16MB
		KeepaliveTime:  5 * time.Second,
	}
}

// NewPluginClient creates a new gRPC client for communicating with a plugin
func NewPluginClient(opts *ClientOptions) *PluginClient {
	if opts == nil {
		opts = DefaultClientOptions()
	}

	return &PluginClient{
		address: opts.Address,
		timeout: opts.Timeout,
	}
}

// Connect establishes a connection to the plugin gRPC server
func (c *PluginClient) Connect(ctx context.Context, address string) models.Result[bool] {
	if c.connected {
		return models.Ok(true)
	}

	// Set up connection options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1024*1024*16), // 16MB
			grpc.MaxCallSendMsgSize(1024*1024*16), // 16MB
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                5 * time.Second,
			Timeout:             1 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(), // Wait for connection to be ready
	}

	// Create connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := grpc.DialContext(connectCtx, address, opts...)
	if err != nil {
		return models.Err[bool](fmt.Errorf("failed to connect to plugin at %s: %w", address, err))
	}

	c.conn = conn
	c.client = proto.NewPluginServiceClient(conn)
	c.address = address
	c.connected = true

	return models.Ok(true)
}

// Disconnect closes the connection to the plugin
func (c *PluginClient) Disconnect() models.Result[bool] {
	if !c.connected || c.conn == nil {
		return models.Ok(true)
	}

	err := c.conn.Close()
	if err != nil {
		return models.Err[bool](fmt.Errorf("failed to close connection: %w", err))
	}

	c.connected = false
	c.conn = nil
	c.client = nil

	return models.Ok(true)
}

// GetInfo retrieves plugin information
func (c *PluginClient) GetInfo(ctx context.Context) models.Result[*plugin.PluginInfo] {
	if !c.connected {
		return models.Err[*plugin.PluginInfo](fmt.Errorf("client not connected"))
	}

	// Create request with timeout
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.GetInfo(reqCtx, &proto.GetInfoRequest{})
	if err != nil {
		return models.Err[*plugin.PluginInfo](fmt.Errorf("failed to get plugin info: %w", err))
	}

	// Convert proto response to plugin info
	info := convertProtoPluginInfo(resp.Info)
	return models.Ok(info)
}

// Assess performs a security assessment
func (c *PluginClient) Assess(ctx context.Context, target *plugin.Target, config *plugin.AssessmentConfig) models.Result[*plugin.AssessResult] {
	if !c.connected {
		return models.Err[*plugin.AssessResult](fmt.Errorf("client not connected"))
	}

	// Convert to proto request
	protoTarget := convertTargetToProto(target)
	protoConfig := convertAssessmentConfigToProto(config)

	req := &proto.AssessRequest{
		RequestId: fmt.Sprintf("client-req-%d", time.Now().UnixNano()),
		Target:    protoTarget,
		Config:    protoConfig,
		Timestamp: timestampNow(),
	}

	// Create request with timeout
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.Assess(reqCtx, req)
	if err != nil {
		return models.Err[*plugin.AssessResult](fmt.Errorf("assessment failed: %w", err))
	}

	if !resp.Success {
		return models.Err[*plugin.AssessResult](fmt.Errorf("plugin assessment failed: %s", resp.ErrorMessage))
	}

	// Convert proto response to assess result
	result := convertProtoAssessResponse(resp)
	return models.Ok(result)
}

// AssessStream performs streaming assessment
func (c *PluginClient) AssessStream(ctx context.Context, requestChan <-chan *plugin.AssessRequest) models.Result[<-chan *plugin.AssessResult] {
	if !c.connected {
		return models.Err[<-chan *plugin.AssessResult](fmt.Errorf("client not connected"))
	}

	stream, err := c.client.StreamAssess(ctx)
	if err != nil {
		return models.Err[<-chan *plugin.AssessResult](fmt.Errorf("failed to create stream: %w", err))
	}

	responseChan := make(chan *plugin.AssessResult, 10)

	// Start goroutine to send requests
	go func() {
		defer func() {
			if err := stream.CloseSend(); err != nil {
				// Log error but don't block
			}
		}()

		for req := range requestChan {
			protoReq := &proto.AssessRequest{
				RequestId: req.RequestID,
				Target:    convertTargetToProto(req.Target),
				Config:    convertAssessmentConfigToProto(req.Config),
				Context:   req.Context,
				Timestamp: timestampNow(),
			}

			if err := stream.Send(protoReq); err != nil {
				close(responseChan)
				return
			}
		}
	}()

	// Start goroutine to receive responses
	go func() {
		defer close(responseChan)

		for {
			resp, err := stream.Recv()
			if err != nil {
				return
			}

			result := convertProtoAssessResponse(resp)
			select {
			case responseChan <- result:
			case <-ctx.Done():
				return
			}
		}
	}()

	return models.Ok((<-chan *plugin.AssessResult)(responseChan))
}

// AssessBatch performs batch assessment
func (c *PluginClient) AssessBatch(ctx context.Context, requests []*plugin.AssessRequest, config *plugin.BatchConfig) models.Result[*plugin.BatchResult] {
	if !c.connected {
		return models.Err[*plugin.BatchResult](fmt.Errorf("client not connected"))
	}

	// Convert requests to proto
	protoRequests := make([]*proto.AssessRequest, len(requests))
	for i, req := range requests {
		protoRequests[i] = &proto.AssessRequest{
			RequestId: req.RequestID,
			Target:    convertTargetToProto(req.Target),
			Config:    convertAssessmentConfigToProto(req.Config),
			Context:   req.Context,
			Timestamp: timestampNow(),
		}
	}

	// Convert batch config
	protoBatchConfig := &proto.BatchConfig{
		MaxConcurrent:  int32(config.MaxConcurrent),
		TimeoutSeconds: int32(config.TimeoutSeconds),
		FailFast:       config.FailFast,
		CollectMetrics: config.CollectMetrics,
	}

	req := &proto.BatchAssessRequest{
		BatchId:  config.BatchID,
		Requests: protoRequests,
		Config:   protoBatchConfig,
	}

	// Create request with extended timeout for batch operations
	batchTimeout := time.Duration(config.TimeoutSeconds)*time.Second + 30*time.Second
	reqCtx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()

	resp, err := c.client.BatchAssess(reqCtx, req)
	if err != nil {
		return models.Err[*plugin.BatchResult](fmt.Errorf("batch assessment failed: %w", err))
	}

	// Convert proto response to batch result
	result := convertProtoBatchResponse(resp)
	return models.Ok(result)
}

// HealthCheck checks the health of the plugin
func (c *PluginClient) HealthCheck(ctx context.Context) models.Result[*plugin.HealthResult] {
	if !c.connected {
		return models.Err[*plugin.HealthResult](fmt.Errorf("client not connected"))
	}

	// Create request with short timeout for health checks
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.client.HealthCheck(reqCtx, &proto.HealthCheckRequest{})
	if err != nil {
		return models.Err[*plugin.HealthResult](fmt.Errorf("health check failed: %w", err))
	}

	healthy := resp.Status == proto.HealthStatus_HEALTH_STATUS_SERVING
	result := &plugin.HealthResult{
		Healthy: healthy,
		Message: resp.Message,
		Details: resp.Details,
	}

	return models.Ok(result)
}

// IsConnected returns whether the client is connected
func (c *PluginClient) IsConnected() bool {
	return c.connected
}

// Address returns the server address
func (c *PluginClient) Address() string {
	return c.address
}

// WaitForReady waits for the connection to be ready
func (c *PluginClient) WaitForReady(ctx context.Context) models.Result[bool] {
	if !c.connected || c.conn == nil {
		return models.Err[bool](fmt.Errorf("client not connected"))
	}

	// Wait for connection to be ready
	for {
		state := c.conn.GetState()
		switch state {
		case connectivity.Ready:
			return models.Ok(true)
		case connectivity.TransientFailure, connectivity.Shutdown:
			return models.Err[bool](fmt.Errorf("connection failed, state: %v", state))
		case connectivity.Idle, connectivity.Connecting:
			// Wait a bit and try again
			select {
			case <-ctx.Done():
				return models.Err[bool](ctx.Err())
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
	}
}

// Ping performs a quick connectivity test
func (c *PluginClient) Ping(ctx context.Context) models.Result[time.Duration] {
	start := time.Now()

	healthResult := c.HealthCheck(ctx)
	if healthResult.IsErr() {
		return models.Err[time.Duration](healthResult.Error())
	}

	duration := time.Since(start)
	return models.Ok(duration)
}

// GetConnectionState returns the current connection state
func (c *PluginClient) GetConnectionState() connectivity.State {
	if c.conn == nil {
		return connectivity.Shutdown
	}
	return c.conn.GetState()
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}
