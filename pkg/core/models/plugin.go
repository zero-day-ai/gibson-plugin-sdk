// Package models provides core business logic models for the Gibson Plugin SDK
package models

import (
	"time"

	"github.com/google/uuid"
)

// PluginInfo contains metadata about a security plugin
// This is the core business logic model with validation and business rules
type PluginInfo struct {
	ID           uuid.UUID              `json:"id" validate:"required"`
	Name         string                 `json:"name" validate:"required,min=1,max=255"`
	Version      string                 `json:"version" validate:"required,semver"`
	Description  string                 `json:"description" validate:"max=1000"`
	Author       string                 `json:"author" validate:"required,max=255"`
	Domains      []SecurityDomain       `json:"domains" validate:"required,min=1"`
	Capabilities []string               `json:"capabilities"`
	Config       map[string]interface{} `json:"config"`
	SDKVersion   string                 `json:"sdk_version" validate:"required,semver"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// AssessRequest contains the target and configuration for security assessment
type AssessRequest struct {
	ID         uuid.UUID              `json:"id" validate:"required"`
	Target     *Target                `json:"target" validate:"required"`
	Config     map[string]interface{} `json:"config"`
	ScanID     string                 `json:"scan_id" validate:"required"`
	Timeout    time.Duration          `json:"timeout" validate:"min=1s,max=1h"`
	Metadata   map[string]string      `json:"metadata"`
	RequestID  string                 `json:"request_id" validate:"required"`
	Timestamp  time.Time              `json:"timestamp"`
	Priority   RequestPriority        `json:"priority"`
	RetryCount int                    `json:"retry_count" validate:"min=0,max=5"`
}

// Target represents the system, API, or resource being assessed
type Target struct {
	ID          uuid.UUID         `json:"id" validate:"required"`
	Name        string            `json:"name" validate:"required,min=1,max=255"`
	Type        TargetType        `json:"type" validate:"required"`
	URL         string            `json:"url" validate:"omitempty,url"`
	Credentials map[string]string `json:"credentials"`
	Config      map[string]string `json:"config"`
	Tags        []string          `json:"tags"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// AssessResponse contains the results of a security assessment
type AssessResponse struct {
	ID            uuid.UUID         `json:"id" validate:"required"`
	RequestID     string            `json:"request_id" validate:"required"`
	ScanID        string            `json:"scan_id" validate:"required"`
	Success       bool              `json:"success"`
	Error         string            `json:"error,omitempty"`
	Completed     bool              `json:"completed"`
	Findings      []*Finding        `json:"findings"`
	StartTime     time.Time         `json:"start_time"`
	EndTime       time.Time         `json:"end_time"`
	Duration      time.Duration     `json:"duration"`
	Metadata      map[string]string `json:"metadata"`
	ResourceUsage *ResourceUsage    `json:"resource_usage,omitempty"`
	Status        ResponseStatus    `json:"status"`
}

// Finding represents a security vulnerability or issue discovered during assessment
type Finding struct {
	ID          uuid.UUID              `json:"id" validate:"required"`
	Title       string                 `json:"title" validate:"required,min=1,max=255"`
	Description string                 `json:"description" validate:"required,min=1,max=2000"`
	Severity    SeverityLevel          `json:"severity" validate:"required"`
	Confidence  ConfidenceLevel        `json:"confidence" validate:"required"`
	Category    string                 `json:"category" validate:"required"`
	Domain      SecurityDomain         `json:"domain" validate:"required"`
	Evidence    map[string]interface{} `json:"evidence"`
	Location    string                 `json:"location"`
	Payload     string                 `json:"payload"`
	Response    string                 `json:"response"`
	Remediation string                 `json:"remediation"`
	References  []string               `json:"references"`
	Timestamp   time.Time              `json:"timestamp"`
	PluginID    string                 `json:"plugin_id" validate:"required"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]string      `json:"metadata"`
	RequestID   string                 `json:"request_id" validate:"required"`
	Verified    bool                   `json:"verified"`
	CVSS        *CVSSScore             `json:"cvss,omitempty"`
}

// SecurityDomain represents the security domain categories
type SecurityDomain string

const (
	DomainModel          SecurityDomain = "model"
	DomainData           SecurityDomain = "data"
	DomainInterface      SecurityDomain = "interface"
	DomainInfrastructure SecurityDomain = "infrastructure"
	DomainOutput         SecurityDomain = "output"
	DomainProcess        SecurityDomain = "process"
)

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

// TargetType represents the type of target being assessed
type TargetType string

const (
	TargetTypeAPI     TargetType = "api"
	TargetTypeModel   TargetType = "model"
	TargetTypeWebsite TargetType = "website"
	TargetTypeService TargetType = "service"
	TargetTypeSystem  TargetType = "system"
)

// RequestPriority represents the priority of an assessment request
type RequestPriority string

const (
	PriorityHigh   RequestPriority = "high"
	PriorityMedium RequestPriority = "medium"
	PriorityLow    RequestPriority = "low"
)

// ResponseStatus represents the status of an assessment response
type ResponseStatus string

const (
	StatusCompleted  ResponseStatus = "completed"
	StatusPartial    ResponseStatus = "partial"
	StatusFailed     ResponseStatus = "failed"
	StatusInProgress ResponseStatus = "in_progress"
	StatusTimeout    ResponseStatus = "timeout"
	StatusCancelled  ResponseStatus = "cancelled"
)

// ResourceUsage tracks resource consumption during plugin execution
type ResourceUsage struct {
	CPUTime    time.Duration `json:"cpu_time"`
	Memory     int64         `json:"memory_bytes" validate:"min=0"`
	NetworkIn  int64         `json:"network_in_bytes" validate:"min=0"`
	NetworkOut int64         `json:"network_out_bytes" validate:"min=0"`
	APICalls   int           `json:"api_calls" validate:"min=0"`
	MaxMemory  int64         `json:"max_memory_bytes" validate:"min=0"`
	Goroutines int           `json:"goroutines" validate:"min=0"`
}

// CVSSScore represents a CVSS vulnerability score
type CVSSScore struct {
	Version string  `json:"version" validate:"required"`
	Vector  string  `json:"vector" validate:"required"`
	Score   float64 `json:"score" validate:"min=0,max=10"`
	Rating  string  `json:"rating" validate:"required"`
}

// SetDefaults sets default values for PluginInfo
func (p *PluginInfo) SetDefaults() {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	if p.Config == nil {
		p.Config = make(map[string]interface{})
	}
}

// SetDefaults sets default values for AssessRequest
func (a *AssessRequest) SetDefaults() {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}
	if a.Priority == "" {
		a.Priority = PriorityMedium
	}
	if a.Timeout == 0 {
		a.Timeout = 5 * time.Minute
	}
	if a.Config == nil {
		a.Config = make(map[string]interface{})
	}
	if a.Metadata == nil {
		a.Metadata = make(map[string]string)
	}
}

// SetDefaults sets default values for Target
func (t *Target) SetDefaults() {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	if t.Config == nil {
		t.Config = make(map[string]string)
	}
	if t.Credentials == nil {
		t.Credentials = make(map[string]string)
	}
}

// SetDefaults sets default values for AssessResponse
func (a *AssessResponse) SetDefaults() {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.StartTime.IsZero() {
		a.StartTime = time.Now()
	}
	if a.EndTime.IsZero() && a.Completed {
		a.EndTime = time.Now()
		a.Duration = a.EndTime.Sub(a.StartTime)
	}
	if a.Status == "" {
		if a.Completed {
			if a.Success {
				a.Status = StatusCompleted
			} else {
				a.Status = StatusFailed
			}
		} else {
			a.Status = StatusInProgress
		}
	}
	if a.Metadata == nil {
		a.Metadata = make(map[string]string)
	}
}

// SetDefaults sets default values for Finding
func (f *Finding) SetDefaults() {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}
	if f.Evidence == nil {
		f.Evidence = make(map[string]interface{})
	}
	if f.Metadata == nil {
		f.Metadata = make(map[string]string)
	}
}

// IsValidDomain checks if a security domain is valid
func IsValidDomain(domain SecurityDomain) bool {
	switch domain {
	case DomainModel, DomainData, DomainInterface, DomainInfrastructure, DomainOutput, DomainProcess:
		return true
	default:
		return false
	}
}

// IsValidSeverity checks if a severity level is valid
func IsValidSeverity(severity SeverityLevel) bool {
	switch severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// IsValidConfidence checks if a confidence level is valid
func IsValidConfidence(confidence ConfidenceLevel) bool {
	switch confidence {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}
