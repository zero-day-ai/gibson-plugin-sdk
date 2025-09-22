// Package models provides database persistence models for the Gibson Plugin SDK
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PluginInfoDB represents the database model for plugin information
// Uses pointers for nullable fields and proper JSON/DB tags for persistence
type PluginInfoDB struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	Version      string    `json:"version" db:"version"`
	Description  *string   `json:"description,omitempty" db:"description"`
	Author       string    `json:"author" db:"author"`
	Domains      *string   `json:"domains,omitempty" db:"domains"`           // JSON array as string
	Capabilities *string   `json:"capabilities,omitempty" db:"capabilities"` // JSON array as string
	Config       *string   `json:"config,omitempty" db:"config"`             // JSON object as string
	SDKVersion   string    `json:"sdk_version" db:"sdk_version"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// AssessRequestDB represents the database model for assessment requests
type AssessRequestDB struct {
	ID         uuid.UUID `json:"id" db:"id"`
	TargetID   uuid.UUID `json:"target_id" db:"target_id"`
	Config     *string   `json:"config,omitempty" db:"config"` // JSON object as string
	ScanID     string    `json:"scan_id" db:"scan_id"`
	Timeout    int64     `json:"timeout" db:"timeout"`             // Duration as nanoseconds
	Metadata   *string   `json:"metadata,omitempty" db:"metadata"` // JSON object as string
	RequestID  string    `json:"request_id" db:"request_id"`
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`
	Priority   string    `json:"priority" db:"priority"`
	RetryCount int       `json:"retry_count" db:"retry_count"`
}

// TargetDB represents the database model for targets
type TargetDB struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Type        string    `json:"type" db:"type"`
	URL         *string   `json:"url,omitempty" db:"url"`
	Credentials *string   `json:"credentials,omitempty" db:"credentials"` // JSON object as string
	Config      *string   `json:"config,omitempty" db:"config"`           // JSON object as string
	Tags        *string   `json:"tags,omitempty" db:"tags"`               // JSON array as string
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// AssessResponseDB represents the database model for assessment responses
type AssessResponseDB struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	RequestID     string     `json:"request_id" db:"request_id"`
	ScanID        string     `json:"scan_id" db:"scan_id"`
	Success       bool       `json:"success" db:"success"`
	Error         *string    `json:"error,omitempty" db:"error"`
	Completed     bool       `json:"completed" db:"completed"`
	StartTime     time.Time  `json:"start_time" db:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty" db:"end_time"`
	Duration      *int64     `json:"duration,omitempty" db:"duration"`             // Duration as nanoseconds
	Metadata      *string    `json:"metadata,omitempty" db:"metadata"`             // JSON object as string
	ResourceUsage *string    `json:"resource_usage,omitempty" db:"resource_usage"` // JSON object as string
	Status        string     `json:"status" db:"status"`
}

// FindingDB represents the database model for security findings
type FindingDB struct {
	ID          uuid.UUID `json:"id" db:"id"`
	ResponseID  uuid.UUID `json:"response_id" db:"response_id"`
	Title       string    `json:"title" db:"title"`
	Description string    `json:"description" db:"description"`
	Severity    string    `json:"severity" db:"severity"`
	Confidence  string    `json:"confidence" db:"confidence"`
	Category    string    `json:"category" db:"category"`
	Domain      string    `json:"domain" db:"domain"`
	Evidence    *string   `json:"evidence,omitempty" db:"evidence"` // JSON object as string
	Location    *string   `json:"location,omitempty" db:"location"`
	Payload     *string   `json:"payload,omitempty" db:"payload"`
	Response    *string   `json:"response,omitempty" db:"response"`
	Remediation *string   `json:"remediation,omitempty" db:"remediation"`
	References  *string   `json:"references,omitempty" db:"references"` // JSON array as string
	Timestamp   time.Time `json:"timestamp" db:"timestamp"`
	PluginID    string    `json:"plugin_id" db:"plugin_id"`
	Tags        *string   `json:"tags,omitempty" db:"tags"`         // JSON array as string
	Metadata    *string   `json:"metadata,omitempty" db:"metadata"` // JSON object as string
	RequestID   string    `json:"request_id" db:"request_id"`
	Verified    bool      `json:"verified" db:"verified"`
	CVSS        *string   `json:"cvss,omitempty" db:"cvss"` // JSON object as string
}

// ResourceUsageDB represents the database model for resource usage
type ResourceUsageDB struct {
	ID         uuid.UUID `json:"id" db:"id"`
	ResponseID uuid.UUID `json:"response_id" db:"response_id"`
	CPUTime    int64     `json:"cpu_time" db:"cpu_time"` // Duration as nanoseconds
	Memory     int64     `json:"memory" db:"memory"`
	NetworkIn  int64     `json:"network_in" db:"network_in"`
	NetworkOut int64     `json:"network_out" db:"network_out"`
	APICalls   int       `json:"api_calls" db:"api_calls"`
	MaxMemory  int64     `json:"max_memory" db:"max_memory"`
	Goroutines int       `json:"goroutines" db:"goroutines"`
}

// JSON marshaling/unmarshaling helpers for complex fields

// StringArray is a helper type for JSON arrays stored as strings
type StringArray []string

// Scan implements the sql.Scanner interface
func (sa *StringArray) Scan(value interface{}) error {
	if value == nil {
		*sa = nil
		return nil
	}

	switch v := value.(type) {
	case string:
		if v == "" {
			*sa = nil
			return nil
		}
		return json.Unmarshal([]byte(v), sa)
	case []byte:
		if len(v) == 0 {
			*sa = nil
			return nil
		}
		return json.Unmarshal(v, sa)
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
}

// Value implements the driver.Valuer interface
func (sa StringArray) Value() (driver.Value, error) {
	if sa == nil {
		return nil, nil
	}
	b, err := json.Marshal(sa)
	return string(b), err
}

// StringMap is a helper type for JSON objects stored as strings
type StringMap map[string]string

// Scan implements the sql.Scanner interface
func (sm *StringMap) Scan(value interface{}) error {
	if value == nil {
		*sm = nil
		return nil
	}

	switch v := value.(type) {
	case string:
		if v == "" {
			*sm = nil
			return nil
		}
		return json.Unmarshal([]byte(v), sm)
	case []byte:
		if len(v) == 0 {
			*sm = nil
			return nil
		}
		return json.Unmarshal(v, sm)
	default:
		return fmt.Errorf("cannot scan %T into StringMap", value)
	}
}

// Value implements the driver.Valuer interface
func (sm StringMap) Value() (driver.Value, error) {
	if sm == nil {
		return nil, nil
	}
	b, err := json.Marshal(sm)
	return string(b), err
}

// InterfaceMap is a helper type for JSON objects with interface{} values stored as strings
type InterfaceMap map[string]interface{}

// Scan implements the sql.Scanner interface
func (im *InterfaceMap) Scan(value interface{}) error {
	if value == nil {
		*im = nil
		return nil
	}

	switch v := value.(type) {
	case string:
		if v == "" {
			*im = nil
			return nil
		}
		return json.Unmarshal([]byte(v), im)
	case []byte:
		if len(v) == 0 {
			*im = nil
			return nil
		}
		return json.Unmarshal(v, im)
	default:
		return fmt.Errorf("cannot scan %T into InterfaceMap", value)
	}
}

// Value implements the driver.Valuer interface
func (im InterfaceMap) Value() (driver.Value, error) {
	if im == nil {
		return nil, nil
	}
	b, err := json.Marshal(im)
	return string(b), err
}

// SetDefaults sets default values for PluginInfoDB
func (p *PluginInfoDB) SetDefaults() {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
}

// SetDefaults sets default values for AssessRequestDB
func (a *AssessRequestDB) SetDefaults() {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}
	if a.Priority == "" {
		a.Priority = "medium"
	}
	if a.Timeout == 0 {
		a.Timeout = int64(5 * time.Minute) // 5 minutes default
	}
}

// SetDefaults sets default values for TargetDB
func (t *TargetDB) SetDefaults() {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
}

// SetDefaults sets default values for AssessResponseDB
func (a *AssessResponseDB) SetDefaults() {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.StartTime.IsZero() {
		a.StartTime = time.Now()
	}
	if a.Status == "" {
		if a.Completed {
			if a.Success {
				a.Status = "completed"
			} else {
				a.Status = "failed"
			}
		} else {
			a.Status = "in_progress"
		}
	}
}

// SetDefaults sets default values for FindingDB
func (f *FindingDB) SetDefaults() {
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}
}
