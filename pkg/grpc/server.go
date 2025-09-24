package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/grpc/proto"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
)

// PluginServer implements the gRPC PluginService for plugins
type PluginServer struct {
	proto.UnimplementedPluginServiceServer

	plugin         plugin.SecurityPlugin
	info           *plugin.PluginInfo
	grpcServer     *grpc.Server
	healthServer   *health.Server
	listener       net.Listener
	shutdownChan   chan struct{}
	shutdownOnce   sync.Once
	requestCounter int64
	requestMutex   sync.Mutex
}

// NewPluginServer creates a new gRPC server for a plugin
func NewPluginServer(p plugin.SecurityPlugin, info *plugin.PluginInfo) *PluginServer {
	return &PluginServer{
		plugin:       p,
		info:         info,
		shutdownChan: make(chan struct{}),
	}
}

// Start starts the gRPC server on the specified port
func (s *PluginServer) Start(port int) error {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	// Create gRPC server with options
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(1024 * 1024 * 16), // 16MB max message size
		grpc.MaxSendMsgSize(1024 * 1024 * 16), // 16MB max message size
		grpc.ConnectionTimeout(30 * time.Second),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Second,
			MaxConnectionAge:      30 * time.Second,
			MaxConnectionAgeGrace: 5 * time.Second,
			Time:                  5 * time.Second,
			Timeout:               1 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	s.grpcServer = grpc.NewServer(opts...)

	// Register the plugin service
	proto.RegisterPluginServiceServer(s.grpcServer, s)

	// Set up health check service
	s.healthServer = health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.grpcServer, s.healthServer)
	s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Start serving in a goroutine
	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the gRPC server
func (s *PluginServer) Stop() {
	s.shutdownOnce.Do(func() {
		close(s.shutdownChan)

		if s.healthServer != nil {
			s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		}

		if s.grpcServer != nil {
			// Graceful stop with timeout
			done := make(chan struct{})
			go func() {
				s.grpcServer.GracefulStop()
				close(done)
			}()

			select {
			case <-done:
				// Graceful stop completed
			case <-time.After(10 * time.Second):
				// Force stop after timeout
				s.grpcServer.Stop()
			}
		}

		if s.listener != nil {
			s.listener.Close()
		}
	})
}

// Address returns the server's listening address
func (s *PluginServer) Address() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// GetInfo implements the GetInfo RPC method
func (s *PluginServer) GetInfo(ctx context.Context, req *proto.GetInfoRequest) (*proto.GetInfoResponse, error) {
	info := &proto.PluginInfo{
		Name:        s.info.Name,
		Version:     s.info.Version,
		Description: s.info.Description,
		Author:      s.info.Author,
		Domain:      convertSecurityDomain(s.info.Domain),
		Capabilities: &proto.PluginCapabilities{
			SupportsStreaming:     s.info.Capabilities.SupportsStreaming,
			SupportsBatch:         s.info.Capabilities.SupportsBatch,
			SupportsConcurrent:    s.info.Capabilities.SupportsConcurrent,
			MaxConcurrentRequests: int32(s.info.Capabilities.MaxConcurrentRequests),
			TimeoutSeconds:        int32(s.info.Capabilities.TimeoutSeconds),
			RequiredPermissions:   s.info.Capabilities.RequiredPermissions,
		},
		Metadata:  s.info.Metadata,
		CreatedAt: timestampFromTime(s.info.CreatedAt),
		UpdatedAt: timestampFromTime(s.info.UpdatedAt),
	}

	// Add supported payload types
	for _, payloadType := range s.info.SupportedPayloadTypes {
		info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, string(payloadType))
	}

	return &proto.GetInfoResponse{
		Info: info,
	}, nil
}

// Assess implements the Assess RPC method
func (s *PluginServer) Assess(ctx context.Context, req *proto.AssessRequest) (*proto.AssessResponse, error) {
	// Generate unique request ID if not provided
	requestID := req.RequestId
	if requestID == "" {
		s.requestMutex.Lock()
		s.requestCounter++
		requestID = fmt.Sprintf("req-%d", s.requestCounter)
		s.requestMutex.Unlock()
	}

	// Convert proto request to plugin request
	target, err := convertProtoTarget(req.Target)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target: %v", err)
	}

	config, err := convertProtoAssessmentConfig(req.Config)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid config: %v", err)
	}

	// Create assess request for the plugin
	assessRequest := &plugin.AssessRequest{
		RequestID: requestID,
		Target:    target,
		Config:    config,
		Context:   req.Context,
	}

	// Call plugin execute method
	result := s.plugin.Execute(ctx, assessRequest)
	if result.IsErr() {
		return &proto.AssessResponse{
			RequestId:    requestID,
			Success:      false,
			ErrorMessage: result.Error().Error(),
			Timestamp:    timestampNow(),
		}, nil
	}

	assessResponse := result.Unwrap()

	// Convert findings to proto
	protoFindings := make([]*proto.Finding, len(assessResponse.Findings))
	for i, finding := range assessResponse.Findings {
		protoFindings[i] = convertFindingToProto(finding)
	}

	return &proto.AssessResponse{
		RequestId: requestID,
		Success:   assessResponse.Success,
		Findings:  protoFindings,
		Metadata: &proto.AssessmentMetadata{
			StartedAt:          timestampFromTime(assessResponse.StartTime),
			CompletedAt:        timestampFromTime(assessResponse.EndTime),
			DurationMs:         int64(assessResponse.Duration.Milliseconds()),
			PayloadsTested:     int32(0), // Not available in AssessResponse
			FindingsCount:      int32(len(assessResponse.Findings)),
			PluginVersion:      s.info.Version,
			PerformanceMetrics: make(map[string]string), // Convert from assessResponse.Metadata if needed
		},
		Timestamp: timestampNow(),
	}, nil
}

// StreamAssess implements the StreamAssess RPC method
func (s *PluginServer) StreamAssess(stream proto.PluginService_StreamAssessServer) error {
	// Check if plugin supports streaming
	if s.info.Capabilities != nil && !s.info.Capabilities.SupportsStreaming {
		return status.Error(codes.Unimplemented, "plugin does not support streaming")
	}

	_, ok := s.plugin.(plugin.StreamingPlugin)
	if !ok {
		return status.Error(codes.Unimplemented, "plugin does not implement streaming interface")
	}

	ctx := stream.Context()

	// For now, process requests sequentially
	// In a full implementation, this would handle concurrent streaming
	for {
		req, err := stream.Recv()
		if err != nil {
			// End of stream or error
			return err
		}

		// Convert proto request to plugin request
		target, err := convertProtoTarget(req.Target)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid target: %v", err)
		}

		config, err := convertProtoAssessmentConfig(req.Config)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid config: %v", err)
		}

		assessRequest := &plugin.AssessRequest{
			RequestID: req.RequestId,
			Target:    target,
			Config:    config,
			Context:   req.Context,
		}

		// Execute assessment
		result := s.plugin.Execute(ctx, assessRequest)
		var response *proto.AssessResponse

		if result.IsErr() {
			response = &proto.AssessResponse{
				RequestId:    req.RequestId,
				Success:      false,
				ErrorMessage: result.Error().Error(),
				Timestamp:    timestampNow(),
			}
		} else {
			assessResponse := result.Unwrap()
			protoFindings := make([]*proto.Finding, len(assessResponse.Findings))
			for i, finding := range assessResponse.Findings {
				protoFindings[i] = convertFindingToProto(finding)
			}

			response = &proto.AssessResponse{
				RequestId: req.RequestId,
				Success:   assessResponse.Success,
				Findings:  protoFindings,
				Timestamp: timestampNow(),
			}
		}

		// Send response
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

// BatchAssess implements the BatchAssess RPC method
func (s *PluginServer) BatchAssess(ctx context.Context, req *proto.BatchAssessRequest) (*proto.BatchAssessResponse, error) {
	// Check if plugin supports batch processing
	if s.info.Capabilities != nil && !s.info.Capabilities.SupportsBatch {
		return nil, status.Error(codes.Unimplemented, "plugin does not support batch processing")
	}

	_, ok := s.plugin.(plugin.BatchPlugin)
	if !ok {
		// Fall back to sequential processing if batch interface not implemented
		responses := make([]*proto.AssessResponse, len(req.Requests))
		startTime := time.Now()

		for i, protoReq := range req.Requests {
			// Convert proto request
			target, err := convertProtoTarget(protoReq.Target)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid target in request %d: %v", i, err)
			}

			config, err := convertProtoAssessmentConfig(protoReq.Config)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid config in request %d: %v", i, err)
			}

			assessRequest := &plugin.AssessRequest{
				RequestID: protoReq.RequestId,
				Target:    target,
				Config:    config,
				Context:   protoReq.Context,
			}

			// Execute assessment
			result := s.plugin.Execute(ctx, assessRequest)

			if result.IsErr() {
				responses[i] = &proto.AssessResponse{
					RequestId:    protoReq.RequestId,
					Success:      false,
					ErrorMessage: result.Error().Error(),
					Timestamp:    timestampNow(),
				}
			} else {
				assessResponse := result.Unwrap()
				protoFindings := make([]*proto.Finding, len(assessResponse.Findings))
				for j, finding := range assessResponse.Findings {
					protoFindings[j] = convertFindingToProto(finding)
				}

				responses[i] = &proto.AssessResponse{
					RequestId: protoReq.RequestId,
					Success:   assessResponse.Success,
					Findings:  protoFindings,
					Timestamp: timestampNow(),
				}
			}
		}

		endTime := time.Now()
		return &proto.BatchAssessResponse{
			BatchId:   req.BatchId,
			Responses: responses,
			Metadata: &proto.BatchMetadata{
				TotalRequests:      int32(len(req.Requests)),
				SuccessfulRequests: int32(len(responses)), // Simplified
				FailedRequests:     0,                     // Simplified
				StartedAt:          timestampFromTime(startTime),
				CompletedAt:        timestampFromTime(endTime),
				TotalDurationMs:    endTime.Sub(startTime).Milliseconds(),
			},
		}, nil
	}

	// If batch plugin interface is implemented, use it
	// (This would require implementing the actual batch interface methods)
	return nil, status.Error(codes.Unimplemented, "batch plugin interface not fully implemented")
}

// HealthCheck implements the HealthCheck RPC method
func (s *PluginServer) HealthCheck(ctx context.Context, req *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	status := proto.HealthStatus_HEALTH_STATUS_SERVING
	message := "Plugin is healthy"
	details := make(map[string]string)

	// Check if plugin implements health check
	if healthChecker, ok := s.plugin.(plugin.HealthChecker); ok {
		pluginHealth := healthChecker.HealthCheck(ctx)
		if pluginHealth.IsErr() {
			status = proto.HealthStatus_HEALTH_STATUS_NOT_SERVING
			message = pluginHealth.Error().Error()
		} else {
			healthResult := pluginHealth.Unwrap()
			if !healthResult.Healthy {
				status = proto.HealthStatus_HEALTH_STATUS_NOT_SERVING
				message = healthResult.Message
			}
			details = healthResult.Details
		}
	}

	// Add server details
	details["server_address"] = s.Address()
	details["plugin_name"] = s.info.Name
	details["plugin_version"] = s.info.Version

	return &proto.HealthCheckResponse{
		Status:  status,
		Message: message,
		Details: details,
	}, nil
}

// defaultLogger is a simple logger implementation
type defaultLogger struct{}

func (l *defaultLogger) Debug(msg string, fields ...interface{}) {
	log.Printf("[DEBUG] %s %v", msg, fields)
}

func (l *defaultLogger) Info(msg string, fields ...interface{}) {
	log.Printf("[INFO] %s %v", msg, fields)
}

func (l *defaultLogger) Warn(msg string, fields ...interface{}) {
	log.Printf("[WARN] %s %v", msg, fields)
}

func (l *defaultLogger) Error(msg string, fields ...interface{}) {
	log.Printf("[ERROR] %s %v", msg, fields)
}
