package grpc

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/grpc/proto"
	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
)

// convertSecurityDomain converts SDK SecurityDomain to proto SecurityDomain
func convertSecurityDomain(domain plugin.SecurityDomain) proto.SecurityDomain {
	switch domain {
	case plugin.DomainModel:
		return proto.SecurityDomain_DOMAIN_MODEL
	case plugin.DomainData:
		return proto.SecurityDomain_DOMAIN_DATA
	case plugin.DomainInterface:
		return proto.SecurityDomain_DOMAIN_INTERFACE
	case plugin.DomainInfrastructure:
		return proto.SecurityDomain_DOMAIN_INFRASTRUCTURE
	case plugin.DomainOutput:
		return proto.SecurityDomain_DOMAIN_OUTPUT
	case plugin.DomainProcess:
		return proto.SecurityDomain_DOMAIN_PROCESS
	default:
		return proto.SecurityDomain_DOMAIN_UNSPECIFIED
	}
}

// convertProtoSecurityDomain converts proto SecurityDomain to SDK SecurityDomain
func convertProtoSecurityDomain(domain proto.SecurityDomain) plugin.SecurityDomain {
	switch domain {
	case proto.SecurityDomain_DOMAIN_MODEL:
		return plugin.DomainModel
	case proto.SecurityDomain_DOMAIN_DATA:
		return plugin.DomainData
	case proto.SecurityDomain_DOMAIN_INTERFACE:
		return plugin.DomainInterface
	case proto.SecurityDomain_DOMAIN_INFRASTRUCTURE:
		return plugin.DomainInfrastructure
	case proto.SecurityDomain_DOMAIN_OUTPUT:
		return plugin.DomainOutput
	case proto.SecurityDomain_DOMAIN_PROCESS:
		return plugin.DomainProcess
	default:
		return ""
	}
}

// convertPayloadType converts SDK PayloadType to proto PayloadType
func convertPayloadType(payloadType plugin.PayloadType) proto.PayloadType {
	switch payloadType {
	case plugin.PayloadTypePrompt:
		return proto.PayloadType_PAYLOAD_TYPE_PROMPT
	case plugin.PayloadTypeQuery:
		return proto.PayloadType_PAYLOAD_TYPE_QUERY
	case plugin.PayloadTypeInput:
		return proto.PayloadType_PAYLOAD_TYPE_INPUT
	case plugin.PayloadTypeCode:
		return proto.PayloadType_PAYLOAD_TYPE_CODE
	case plugin.PayloadTypeData:
		return proto.PayloadType_PAYLOAD_TYPE_DATA
	case plugin.PayloadTypeScript:
		return proto.PayloadType_PAYLOAD_TYPE_SCRIPT
	default:
		return proto.PayloadType_PAYLOAD_TYPE_UNSPECIFIED
	}
}

// convertProtoPayloadType converts proto PayloadType to SDK PayloadType
func convertProtoPayloadType(payloadType proto.PayloadType) plugin.PayloadType {
	switch payloadType {
	case proto.PayloadType_PAYLOAD_TYPE_PROMPT:
		return plugin.PayloadTypePrompt
	case proto.PayloadType_PAYLOAD_TYPE_QUERY:
		return plugin.PayloadTypeQuery
	case proto.PayloadType_PAYLOAD_TYPE_INPUT:
		return plugin.PayloadTypeInput
	case proto.PayloadType_PAYLOAD_TYPE_CODE:
		return plugin.PayloadTypeCode
	case proto.PayloadType_PAYLOAD_TYPE_DATA:
		return plugin.PayloadTypeData
	case proto.PayloadType_PAYLOAD_TYPE_SCRIPT:
		return plugin.PayloadTypeScript
	default:
		return ""
	}
}

// convertSeverityLevel converts SDK SeverityLevel to proto SeverityLevel
func convertSeverityLevel(severity plugin.SeverityLevel) proto.SeverityLevel {
	switch severity {
	case plugin.SeverityInfo:
		return proto.SeverityLevel_SEVERITY_INFO
	case plugin.SeverityLow:
		return proto.SeverityLevel_SEVERITY_LOW
	case plugin.SeverityMedium:
		return proto.SeverityLevel_SEVERITY_MEDIUM
	case plugin.SeverityHigh:
		return proto.SeverityLevel_SEVERITY_HIGH
	case plugin.SeverityCritical:
		return proto.SeverityLevel_SEVERITY_CRITICAL
	default:
		return proto.SeverityLevel_SEVERITY_UNSPECIFIED
	}
}

// convertProtoSeverityLevel converts proto SeverityLevel to SDK SeverityLevel
func convertProtoSeverityLevel(severity proto.SeverityLevel) plugin.SeverityLevel {
	switch severity {
	case proto.SeverityLevel_SEVERITY_INFO:
		return plugin.SeverityInfo
	case proto.SeverityLevel_SEVERITY_LOW:
		return plugin.SeverityLow
	case proto.SeverityLevel_SEVERITY_MEDIUM:
		return plugin.SeverityMedium
	case proto.SeverityLevel_SEVERITY_HIGH:
		return plugin.SeverityHigh
	case proto.SeverityLevel_SEVERITY_CRITICAL:
		return plugin.SeverityCritical
	default:
		return plugin.SeverityInfo
	}
}

// convertTargetToProto converts SDK Target to proto Target
func convertTargetToProto(target *plugin.Target) *proto.Target {
	if target == nil {
		return nil
	}

	protoTarget := &proto.Target{
		Id:            target.ID,
		Name:          target.Name,
		Type:          target.Type,
		Endpoint:      target.Endpoint,
		Configuration: target.Configuration,
		Tags:          target.Tags,
		Metadata:      target.Metadata,
	}

	if target.Credentials != nil {
		protoTarget.Credentials = &proto.Credentials{
			Type:      target.Credentials.Type,
			Data:      target.Credentials.Data,
			Encrypted: target.Credentials.Encrypted,
		}
	}

	return protoTarget
}

// convertProtoTarget converts proto Target to SDK Target
func convertProtoTarget(protoTarget *proto.Target) (*plugin.Target, error) {
	if protoTarget == nil {
		return nil, nil
	}

	target := &plugin.Target{
		ID:            protoTarget.Id,
		Name:          protoTarget.Name,
		Type:          protoTarget.Type,
		Endpoint:      protoTarget.Endpoint,
		Configuration: protoTarget.Configuration,
		Tags:          protoTarget.Tags,
		Metadata:      protoTarget.Metadata,
	}

	if protoTarget.Credentials != nil {
		target.Credentials = &plugin.Credentials{
			Type:      protoTarget.Credentials.Type,
			Data:      protoTarget.Credentials.Data,
			Encrypted: protoTarget.Credentials.Encrypted,
		}
	}

	return target, nil
}

// convertAssessmentConfigToProto converts SDK AssessmentConfig to proto AssessmentConfig
func convertAssessmentConfigToProto(config *plugin.AssessmentConfig) *proto.AssessmentConfig {
	if config == nil {
		return nil
	}

	protoConfig := &proto.AssessmentConfig{
		Domain:              convertSecurityDomain(config.Domain),
		MaxFindings:         int32(config.MaxFindings),
		TimeoutSeconds:      int32(config.TimeoutSeconds),
		EnableStreaming:     config.EnableStreaming,
		ConcurrentExecution: config.ConcurrentExecution,
	}

	// Convert payload types
	for _, payloadType := range config.PayloadTypes {
		protoConfig.PayloadTypes = append(protoConfig.PayloadTypes, convertPayloadType(payloadType))
	}

	// Note: Options conversion would require more complex handling of google.protobuf.Any
	// For now, we'll skip this field as it requires specific marshaling

	return protoConfig
}

// convertProtoAssessmentConfig converts proto AssessmentConfig to SDK AssessmentConfig
func convertProtoAssessmentConfig(protoConfig *proto.AssessmentConfig) (*plugin.AssessmentConfig, error) {
	if protoConfig == nil {
		return nil, nil
	}

	config := &plugin.AssessmentConfig{
		Domain:              convertProtoSecurityDomain(protoConfig.Domain),
		MaxFindings:         int(protoConfig.MaxFindings),
		TimeoutSeconds:      int(protoConfig.TimeoutSeconds),
		EnableStreaming:     protoConfig.EnableStreaming,
		ConcurrentExecution: protoConfig.ConcurrentExecution,
		Options:             make(map[string]interface{}),
	}

	// Convert payload types
	for _, protoPayloadType := range protoConfig.PayloadTypes {
		payloadType := convertProtoPayloadType(protoPayloadType)
		if payloadType != "" {
			config.PayloadTypes = append(config.PayloadTypes, payloadType)
		}
	}

	return config, nil
}

// convertFindingToProto converts SDK Finding to proto Finding
func convertFindingToProto(finding *plugin.Finding) *proto.Finding {
	if finding == nil {
		return nil
	}

	protoFinding := &proto.Finding{
		Id:           finding.ID,
		Title:        finding.Title,
		Description:  finding.Description,
		Severity:     convertSeverityLevel(finding.Severity),
		Domain:       convertSecurityDomain(finding.Domain),
		PayloadType:  convertPayloadType(finding.PayloadType),
		Payload:      finding.Payload,
		Location:     finding.Location,
		Tags:         finding.Tags,
		Metadata:     finding.Metadata,
		DiscoveredAt: timestampFromTime(finding.DiscoveredAt),
	}

	if finding.Evidence != nil {
		protoFinding.Evidence = &proto.Evidence{
			Type:        finding.Evidence.Type,
			Data:        finding.Evidence.Data,
			Attachments: finding.Evidence.Attachments,
			Context:     finding.Evidence.Context,
		}
	}

	if finding.Remediation != nil {
		protoFinding.Remediation = &proto.Remediation{
			Description: finding.Remediation.Description,
			Steps:       finding.Remediation.Steps,
			Priority:    finding.Remediation.Priority,
			Effort:      finding.Remediation.Effort,
			References:  finding.Remediation.References,
		}
	}

	return protoFinding
}

// convertProtoFinding converts proto Finding to SDK Finding
func convertProtoFinding(protoFinding *proto.Finding) *plugin.Finding {
	if protoFinding == nil {
		return nil
	}

	finding := &plugin.Finding{
		ID:           protoFinding.Id,
		Title:        protoFinding.Title,
		Description:  protoFinding.Description,
		Severity:     convertProtoSeverityLevel(protoFinding.Severity),
		Domain:       convertProtoSecurityDomain(protoFinding.Domain),
		PayloadType:  convertProtoPayloadType(protoFinding.PayloadType),
		Payload:      protoFinding.Payload,
		Location:     protoFinding.Location,
		Tags:         protoFinding.Tags,
		Metadata:     protoFinding.Metadata,
		DiscoveredAt: timeFromTimestamp(protoFinding.DiscoveredAt),
	}

	if protoFinding.Evidence != nil {
		finding.Evidence = &plugin.Evidence{
			Type:        protoFinding.Evidence.Type,
			Data:        protoFinding.Evidence.Data,
			Attachments: protoFinding.Evidence.Attachments,
			Context:     protoFinding.Evidence.Context,
		}
	}

	if protoFinding.Remediation != nil {
		finding.Remediation = &plugin.Remediation{
			Description: protoFinding.Remediation.Description,
			Steps:       protoFinding.Remediation.Steps,
			Priority:    protoFinding.Remediation.Priority,
			Effort:      protoFinding.Remediation.Effort,
			References:  protoFinding.Remediation.References,
		}
	}

	return finding
}

// convertProtoPluginInfo converts proto PluginInfo to SDK PluginInfo
func convertProtoPluginInfo(protoInfo *proto.PluginInfo) *plugin.PluginInfo {
	if protoInfo == nil {
		return nil
	}

	info := &plugin.PluginInfo{
		Name:        protoInfo.Name,
		Version:     protoInfo.Version,
		Description: protoInfo.Description,
		Author:      protoInfo.Author,
		Domain:      convertProtoSecurityDomain(protoInfo.Domain),
		Metadata:    protoInfo.Metadata,
		CreatedAt:   timeFromTimestamp(protoInfo.CreatedAt),
		UpdatedAt:   timeFromTimestamp(protoInfo.UpdatedAt),
	}

	// Convert supported payload types
	for _, payloadTypeStr := range protoInfo.SupportedPayloadTypes {
		// Convert string back to PayloadType
		switch payloadTypeStr {
		case "prompt":
			info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, plugin.PayloadTypePrompt)
		case "query":
			info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, plugin.PayloadTypeQuery)
		case "input":
			info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, plugin.PayloadTypeInput)
		case "code":
			info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, plugin.PayloadTypeCode)
		case "data":
			info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, plugin.PayloadTypeData)
		case "script":
			info.SupportedPayloadTypes = append(info.SupportedPayloadTypes, plugin.PayloadTypeScript)
		}
	}

	if protoInfo.Capabilities != nil {
		info.Capabilities = &plugin.PluginCapabilities{
			SupportsStreaming:     protoInfo.Capabilities.SupportsStreaming,
			SupportsBatch:         protoInfo.Capabilities.SupportsBatch,
			SupportsConcurrent:    protoInfo.Capabilities.SupportsConcurrent,
			MaxConcurrentRequests: int(protoInfo.Capabilities.MaxConcurrentRequests),
			TimeoutSeconds:        int(protoInfo.Capabilities.TimeoutSeconds),
			RequiredPermissions:   protoInfo.Capabilities.RequiredPermissions,
		}
	}

	return info
}

// convertProtoAssessResponse converts proto AssessResponse to SDK AssessResult
func convertProtoAssessResponse(protoResp *proto.AssessResponse) *plugin.AssessResult {
	if protoResp == nil {
		return nil
	}

	result := &plugin.AssessResult{
		RequestID:    protoResp.RequestId,
		Success:      protoResp.Success,
		ErrorMessage: protoResp.ErrorMessage,
	}

	// Convert findings
	for _, protoFinding := range protoResp.Findings {
		finding := convertProtoFinding(protoFinding)
		if finding != nil {
			result.Findings = append(result.Findings, finding)
		}
	}

	// Convert metadata
	if protoResp.Metadata != nil {
		result.Metadata = &plugin.AssessmentMetadata{
			StartedAt:          timeFromTimestamp(protoResp.Metadata.StartedAt),
			CompletedAt:        timeFromTimestamp(protoResp.Metadata.CompletedAt),
			DurationMs:         protoResp.Metadata.DurationMs,
			PayloadsTested:     int(protoResp.Metadata.PayloadsTested),
			PluginVersion:      protoResp.Metadata.PluginVersion,
			PerformanceMetrics: protoResp.Metadata.PerformanceMetrics,
		}
	}

	return result
}

// convertProtoBatchResponse converts proto BatchAssessResponse to SDK BatchResult
func convertProtoBatchResponse(protoResp *proto.BatchAssessResponse) *plugin.BatchResult {
	if protoResp == nil {
		return nil
	}

	result := &plugin.BatchResult{
		BatchID: protoResp.BatchId,
	}

	// Convert responses
	for _, protoResponse := range protoResp.Responses {
		response := convertProtoAssessResponse(protoResponse)
		if response != nil {
			result.Responses = append(result.Responses, response)
		}
	}

	// Convert metadata
	if protoResp.Metadata != nil {
		result.Metadata = &plugin.BatchMetadata{
			TotalRequests:      int(protoResp.Metadata.TotalRequests),
			SuccessfulRequests: int(protoResp.Metadata.SuccessfulRequests),
			FailedRequests:     int(protoResp.Metadata.FailedRequests),
			StartedAt:          timeFromTimestamp(protoResp.Metadata.StartedAt),
			CompletedAt:        timeFromTimestamp(protoResp.Metadata.CompletedAt),
			TotalDurationMs:    protoResp.Metadata.TotalDurationMs,
		}
	}

	return result
}

// timestampFromTime converts time.Time to protobuf Timestamp
func timestampFromTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// timeFromTimestamp converts protobuf Timestamp to time.Time
func timeFromTimestamp(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// timestampNow returns current time as protobuf Timestamp
func timestampNow() *timestamppb.Timestamp {
	return timestamppb.Now()
}
