// Package plugin defines the types used by Gibson Framework security plugins
package plugin

import (
	"time"
)

// PluginInfo contains metadata about a security plugin
type PluginInfo struct {
	Name                  string              `json:"name"`
	Version               string              `json:"version"`
	Description           string              `json:"description"`
	Author                string              `json:"author"`
	Domain                SecurityDomain      `json:"domain"`                  // Primary security domain
	SupportedPayloadTypes []PayloadType       `json:"supported_payload_types"` // Supported payload types
	Capabilities          *PluginCapabilities `json:"capabilities"`            // Plugin capabilities
	Metadata              map[string]string   `json:"metadata"`                // Additional metadata
	CreatedAt             time.Time           `json:"created_at"`
	UpdatedAt             time.Time           `json:"updated_at"`

	// Legacy fields (deprecated, but kept for compatibility)
	Domains    []SecurityDomain       `json:"domains,omitempty"`     // Security domains this plugin covers
	Config     map[string]interface{} `json:"config,omitempty"`      // Configuration schema
	SDKVersion string                 `json:"sdk_version,omitempty"` // SDK version compatibility
}

// SecurityDomain is defined in domains.go

// AssessRequest contains the target and configuration for security assessment
type AssessRequest struct {
	// Request tracking
	RequestID string `json:"request_id"`

	// Target information
	Target *Target `json:"target"`

	// Assessment configuration
	Config  *AssessmentConfig `json:"config"`
	Context map[string]string `json:"context"`

	// Legacy fields (deprecated, but kept for compatibility)
	ScanID    string            `json:"scan_id,omitempty"`
	Timeout   time.Duration     `json:"timeout,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp,omitempty"`
}

// Target represents the system, API, or resource being assessed
type Target struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`          // e.g., "api", "model", "website"
	Endpoint      string            `json:"endpoint"`      // Target endpoint/URL
	Configuration map[string]string `json:"configuration"` // Target configuration
	Credentials   *Credentials      `json:"credentials,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`

	// Legacy fields (deprecated, but kept for compatibility)
	URL    string            `json:"url,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

// AssessResponse contains the results of a security assessment
type AssessResponse struct {
	// Overall assessment result
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Completed bool   `json:"completed"`

	// Security findings
	Findings []*Finding `json:"findings"`

	// Assessment metadata
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
	Duration  time.Duration     `json:"duration"`
	Metadata  map[string]string `json:"metadata"`

	// Resource usage
	ResourceUsage *ResourceUsage `json:"resource_usage,omitempty"`

	// Request tracking
	RequestID string `json:"request_id"`
	ScanID    string `json:"scan_id"`
}

// BatchAssessResponse contains results from batch processing
type BatchAssessResponse struct {
	// Overall batch result
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Completed bool   `json:"completed"`

	// Individual responses
	Responses []*AssessResponse `json:"responses"`

	// Batch metadata
	BatchSize     int               `json:"batch_size"`
	ProcessedSize int               `json:"processed_size"`
	StartTime     time.Time         `json:"start_time"`
	EndTime       time.Time         `json:"end_time"`
	Duration      time.Duration     `json:"duration"`
	Metadata      map[string]string `json:"metadata"`
}

// Finding represents a security vulnerability or issue discovered during assessment
type Finding struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Severity     SeverityLevel     `json:"severity"`
	Domain       SecurityDomain    `json:"domain"`
	PayloadType  PayloadType       `json:"payload_type"`
	Payload      string            `json:"payload,omitempty"`
	Location     string            `json:"location,omitempty"`
	Evidence     *Evidence         `json:"evidence,omitempty"`
	Remediation  *Remediation      `json:"remediation,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`

	// Legacy fields (deprecated, but kept for compatibility)
	Confidence   ConfidenceLevel        `json:"confidence,omitempty"`
	Category     string                 `json:"category,omitempty"`
	EvidenceData map[string]interface{} `json:"evidence_data,omitempty"`
	Response     string                 `json:"response,omitempty"`
	References   []string               `json:"references,omitempty"`
	Timestamp    time.Time              `json:"timestamp,omitempty"`
	PluginID     string                 `json:"plugin_id,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
}

// SeverityLevel represents the severity of a security finding
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "critical"
	SeverityHigh     SeverityLevel = "high"
	SeverityMedium   SeverityLevel = "medium"
	SeverityLow      SeverityLevel = "low"
	SeverityInfo     SeverityLevel = "info"
)

// ConfidenceLevel represents confidence in a security finding
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "high"
	ConfidenceMedium ConfidenceLevel = "medium"
	ConfidenceLow    ConfidenceLevel = "low"
)

// ResourceUsage tracks resource consumption during plugin execution
type ResourceUsage struct {
	CPUTime    time.Duration `json:"cpu_time"`
	Memory     int64         `json:"memory_bytes"`
	NetworkIn  int64         `json:"network_in_bytes"`
	NetworkOut int64         `json:"network_out_bytes"`
	APICalls   int           `json:"api_calls"`
	MaxMemory  int64         `json:"max_memory_bytes"`
	Goroutines int           `json:"goroutines"`
}

// ValidationResult contains the result of request validation
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Message string   `json:"message"`
	Errors  []string `json:"errors,omitempty"`
}

// HealthStatus represents the health status of a plugin
type HealthStatus struct {
	Status    HealthStatusType       `json:"status"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// HealthStatusType represents the health status types
type HealthStatusType string

const (
	HealthStatusHealthy   HealthStatusType = "healthy"
	HealthStatusUnhealthy HealthStatusType = "unhealthy"
	HealthStatusDegraded  HealthStatusType = "degraded"
	HealthStatusUnknown   HealthStatusType = "unknown"
)

// ConfigSchema defines the configuration schema for a plugin
type ConfigSchema struct {
	Properties map[string]*ConfigProperty `json:"properties"`
	Required   []string                   `json:"required"`
	Version    string                     `json:"version"`
}

// ConfigProperty defines a single configuration property
type ConfigProperty struct {
	Type        string      `json:"type"` // string, int, bool, array, object
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
	Required    bool        `json:"required"`
	Validation  *Validation `json:"validation,omitempty"`
}

// Validation defines validation rules for configuration properties
type Validation struct {
	MinLength *int     `json:"min_length,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
	Pattern   *string  `json:"pattern,omitempty"` // regex pattern
	Options   []string `json:"options,omitempty"` // enum values
	Min       *float64 `json:"min,omitempty"`     // for numeric types
	Max       *float64 `json:"max,omitempty"`     // for numeric types
}

// PayloadType represents different types of security payloads
type PayloadType string

const (
	PayloadTypePrompt PayloadType = "prompt"
	PayloadTypeQuery  PayloadType = "query"
	PayloadTypeInput  PayloadType = "input"
	PayloadTypeCode   PayloadType = "code"
	PayloadTypeData   PayloadType = "data"
	PayloadTypeScript PayloadType = "script"
)

// AssessmentConfig defines configuration for security assessments
type AssessmentConfig struct {
	Domain              SecurityDomain         `json:"domain"`
	PayloadTypes        []PayloadType          `json:"payload_types"`
	MaxFindings         int                    `json:"max_findings"`
	TimeoutSeconds      int                    `json:"timeout_seconds"`
	EnableStreaming     bool                   `json:"enable_streaming"`
	ConcurrentExecution bool                   `json:"concurrent_execution"`
	Options             map[string]interface{} `json:"options"`
}

// AssessResult contains the result of a security assessment
type AssessResult struct {
	RequestID    string              `json:"request_id"`
	Success      bool                `json:"success"`
	ErrorMessage string              `json:"error_message,omitempty"`
	Findings     []*Finding          `json:"findings"`
	Metadata     *AssessmentMetadata `json:"metadata"`
}

// AssessmentMetadata contains metadata about the assessment execution
type AssessmentMetadata struct {
	StartedAt          time.Time         `json:"started_at"`
	CompletedAt        time.Time         `json:"completed_at"`
	DurationMs         int64             `json:"duration_ms"`
	PayloadsTested     int               `json:"payloads_tested"`
	PluginVersion      string            `json:"plugin_version"`
	PerformanceMetrics map[string]string `json:"performance_metrics"`
}

// BatchConfig defines configuration for batch assessments
type BatchConfig struct {
	BatchID        string `json:"batch_id"`
	MaxConcurrent  int    `json:"max_concurrent"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	FailFast       bool   `json:"fail_fast"`
	CollectMetrics bool   `json:"collect_metrics"`
}

// BatchResult contains the result of a batch assessment
type BatchResult struct {
	BatchID   string          `json:"batch_id"`
	Responses []*AssessResult `json:"responses"`
	Metadata  *BatchMetadata  `json:"metadata"`
}

// BatchMetadata contains metadata about batch execution
type BatchMetadata struct {
	TotalRequests      int       `json:"total_requests"`
	SuccessfulRequests int       `json:"successful_requests"`
	FailedRequests     int       `json:"failed_requests"`
	StartedAt          time.Time `json:"started_at"`
	CompletedAt        time.Time `json:"completed_at"`
	TotalDurationMs    int64     `json:"total_duration_ms"`
}

// HealthResult contains the result of a health check
type HealthResult struct {
	Healthy bool              `json:"healthy"`
	Message string            `json:"message"`
	Details map[string]string `json:"details"`
}

// PluginCapabilities defines what capabilities a plugin supports
type PluginCapabilities struct {
	SupportsStreaming     bool     `json:"supports_streaming"`
	SupportsBatch         bool     `json:"supports_batch"`
	SupportsConcurrent    bool     `json:"supports_concurrent"`
	MaxConcurrentRequests int      `json:"max_concurrent_requests"`
	TimeoutSeconds        int      `json:"timeout_seconds"`
	RequiredPermissions   []string `json:"required_permissions"`
}

// Credentials contains authentication information
type Credentials struct {
	Type      string            `json:"type"`
	Data      map[string]string `json:"data"`
	Encrypted bool              `json:"encrypted"`
}

// Evidence contains evidence supporting a security finding
type Evidence struct {
	Type        string            `json:"type"`
	Data        string            `json:"data"`
	Attachments []string          `json:"attachments"`
	Context     map[string]string `json:"context"`
}

// Remediation contains remediation information for a finding
type Remediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Priority    string   `json:"priority"`
	Effort      string   `json:"effort"`
	References  []string `json:"references"`
}

// PluginContext provides context for plugin execution
type PluginContext struct {
	RequestID string            `json:"request_id"`
	Target    *Target           `json:"target"`
	Context   map[string]string `json:"context"`
	Logger    Logger            `json:"-"`
}

// Logger interface for plugin logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}
