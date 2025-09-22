package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestPluginInfo_SetDefaults(t *testing.T) {
	info := &PluginInfo{}
	info.SetDefaults()

	assert.NotEqual(t, uuid.Nil, info.ID)
	assert.False(t, info.CreatedAt.IsZero())
	assert.False(t, info.UpdatedAt.IsZero())
	assert.NotNil(t, info.Config)
}

func TestAssessRequest_SetDefaults(t *testing.T) {
	request := &AssessRequest{}
	request.SetDefaults()

	assert.NotEqual(t, uuid.Nil, request.ID)
	assert.False(t, request.Timestamp.IsZero())
	assert.Equal(t, PriorityMedium, request.Priority)
	assert.Equal(t, 5*time.Minute, request.Timeout)
	assert.NotNil(t, request.Config)
	assert.NotNil(t, request.Metadata)
}

func TestTarget_SetDefaults(t *testing.T) {
	target := &Target{}
	target.SetDefaults()

	assert.NotEqual(t, uuid.Nil, target.ID)
	assert.False(t, target.CreatedAt.IsZero())
	assert.False(t, target.UpdatedAt.IsZero())
	assert.NotNil(t, target.Config)
	assert.NotNil(t, target.Credentials)
}

func TestAssessResponse_SetDefaults(t *testing.T) {
	// Test with completed response
	response := &AssessResponse{
		Success:   true,
		Completed: true,
	}
	response.SetDefaults()

	assert.NotEqual(t, uuid.Nil, response.ID)
	assert.False(t, response.StartTime.IsZero())
	assert.False(t, response.EndTime.IsZero())
	assert.True(t, response.Duration > 0)
	assert.Equal(t, StatusCompleted, response.Status)
	assert.NotNil(t, response.Metadata)

	// Test with failed response
	response = &AssessResponse{
		Success:   false,
		Completed: true,
	}
	response.SetDefaults()

	assert.Equal(t, StatusFailed, response.Status)

	// Test with in-progress response
	response = &AssessResponse{
		Success:   false,
		Completed: false,
	}
	response.SetDefaults()

	assert.Equal(t, StatusInProgress, response.Status)
}

func TestFinding_SetDefaults(t *testing.T) {
	finding := &Finding{}
	finding.SetDefaults()

	assert.NotEqual(t, uuid.Nil, finding.ID)
	assert.False(t, finding.Timestamp.IsZero())
	assert.NotNil(t, finding.Evidence)
	assert.NotNil(t, finding.Metadata)
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   SecurityDomain
		expected bool
	}{
		{"valid model domain", DomainModel, true},
		{"valid data domain", DomainData, true},
		{"valid interface domain", DomainInterface, true},
		{"valid infrastructure domain", DomainInfrastructure, true},
		{"valid output domain", DomainOutput, true},
		{"valid process domain", DomainProcess, true},
		{"invalid domain", SecurityDomain("invalid"), false},
		{"empty domain", SecurityDomain(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidDomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity SeverityLevel
		expected bool
	}{
		{"valid critical severity", SeverityCritical, true},
		{"valid high severity", SeverityHigh, true},
		{"valid medium severity", SeverityMedium, true},
		{"valid low severity", SeverityLow, true},
		{"valid info severity", SeverityInfo, true},
		{"invalid severity", SeverityLevel("invalid"), false},
		{"empty severity", SeverityLevel(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidSeverity(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence ConfidenceLevel
		expected   bool
	}{
		{"valid high confidence", ConfidenceHigh, true},
		{"valid medium confidence", ConfidenceMedium, true},
		{"valid low confidence", ConfidenceLow, true},
		{"invalid confidence", ConfidenceLevel("invalid"), false},
		{"empty confidence", ConfidenceLevel(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidConfidence(tt.confidence)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityDomainConstants(t *testing.T) {
	assert.Equal(t, SecurityDomain("model"), DomainModel)
	assert.Equal(t, SecurityDomain("data"), DomainData)
	assert.Equal(t, SecurityDomain("interface"), DomainInterface)
	assert.Equal(t, SecurityDomain("infrastructure"), DomainInfrastructure)
	assert.Equal(t, SecurityDomain("output"), DomainOutput)
	assert.Equal(t, SecurityDomain("process"), DomainProcess)
}

func TestSeverityLevelConstants(t *testing.T) {
	assert.Equal(t, SeverityLevel("critical"), SeverityCritical)
	assert.Equal(t, SeverityLevel("high"), SeverityHigh)
	assert.Equal(t, SeverityLevel("medium"), SeverityMedium)
	assert.Equal(t, SeverityLevel("low"), SeverityLow)
	assert.Equal(t, SeverityLevel("info"), SeverityInfo)
}

func TestConfidenceLevelConstants(t *testing.T) {
	assert.Equal(t, ConfidenceLevel("high"), ConfidenceHigh)
	assert.Equal(t, ConfidenceLevel("medium"), ConfidenceMedium)
	assert.Equal(t, ConfidenceLevel("low"), ConfidenceLow)
}

func TestTargetTypeConstants(t *testing.T) {
	assert.Equal(t, TargetType("api"), TargetTypeAPI)
	assert.Equal(t, TargetType("model"), TargetTypeModel)
	assert.Equal(t, TargetType("website"), TargetTypeWebsite)
	assert.Equal(t, TargetType("service"), TargetTypeService)
	assert.Equal(t, TargetType("system"), TargetTypeSystem)
}

func TestRequestPriorityConstants(t *testing.T) {
	assert.Equal(t, RequestPriority("high"), PriorityHigh)
	assert.Equal(t, RequestPriority("medium"), PriorityMedium)
	assert.Equal(t, RequestPriority("low"), PriorityLow)
}

func TestResponseStatusConstants(t *testing.T) {
	assert.Equal(t, ResponseStatus("completed"), StatusCompleted)
	assert.Equal(t, ResponseStatus("partial"), StatusPartial)
	assert.Equal(t, ResponseStatus("failed"), StatusFailed)
	assert.Equal(t, ResponseStatus("in_progress"), StatusInProgress)
	assert.Equal(t, ResponseStatus("timeout"), StatusTimeout)
	assert.Equal(t, ResponseStatus("cancelled"), StatusCancelled)
}

func TestPluginInfo_Validation(t *testing.T) {
	// Test complete plugin info
	info := &PluginInfo{
		Name:         "test-plugin",
		Version:      "1.0.0",
		Description:  "Test plugin for security assessments",
		Author:       "Security Team",
		Domains:      []SecurityDomain{DomainInterface, DomainData},
		Capabilities: []string{"streaming", "batch"},
		Config: map[string]interface{}{
			"timeout": 30,
			"retries": 3,
		},
		SDKVersion: "1.0.0",
	}
	info.SetDefaults()

	assert.NotEqual(t, uuid.Nil, info.ID)
	assert.NotEmpty(t, info.Name)
	assert.NotEmpty(t, info.Version)
	assert.NotEmpty(t, info.Author)
	assert.NotEmpty(t, info.Domains)
	assert.False(t, info.CreatedAt.IsZero())
	assert.False(t, info.UpdatedAt.IsZero())
}

func TestAssessRequest_Validation(t *testing.T) {
	// Test complete assess request
	request := &AssessRequest{
		Target: &Target{
			Name: "Test API",
			Type: TargetTypeAPI,
			URL:  "https://api.example.com",
		},
		ScanID:    "scan-123",
		RequestID: "req-456",
	}
	request.SetDefaults()

	assert.NotEqual(t, uuid.Nil, request.ID)
	assert.NotEmpty(t, request.ScanID)
	assert.NotEmpty(t, request.RequestID)
	assert.NotNil(t, request.Target)
	assert.Equal(t, PriorityMedium, request.Priority)
	assert.Equal(t, 5*time.Minute, request.Timeout)
}

func TestTarget_Validation(t *testing.T) {
	// Test complete target
	target := &Target{
		Name: "Test Target",
		Type: TargetTypeAPI,
		URL:  "https://example.com",
		Config: map[string]string{
			"auth_type": "bearer",
			"timeout":   "30s",
		},
		Credentials: map[string]string{
			"token": "encrypted-token",
		},
		Tags: []string{"production", "api", "v1"},
	}
	target.SetDefaults()

	assert.NotEqual(t, uuid.Nil, target.ID)
	assert.NotEmpty(t, target.Name)
	assert.NotEmpty(t, target.Type)
	assert.NotEmpty(t, target.URL)
	assert.False(t, target.CreatedAt.IsZero())
	assert.False(t, target.UpdatedAt.IsZero())
}

func TestFinding_Validation(t *testing.T) {
	// Test complete finding
	finding := &Finding{
		Title:       "SQL Injection Vulnerability",
		Description: "Detected potential SQL injection in login form",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Category:    "injection",
		Domain:      DomainInterface,
		Evidence: map[string]interface{}{
			"payload":  "' OR 1=1--",
			"response": "SQL error message",
		},
		Location:    "/api/login",
		Payload:     "admin' OR 1=1--",
		Response:    "Internal server error",
		Remediation: "Use parameterized queries",
		References:  []string{"OWASP-A03", "CWE-89"},
		PluginID:    "sql-injection-detector",
		Tags:        []string{"sql", "injection", "high-risk"},
		Metadata: map[string]string{
			"scan_time": "2023-01-01T10:00:00Z",
		},
		RequestID: "req-789",
		Verified:  true,
		CVSS: &CVSSScore{
			Version: "3.1",
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Score:   9.8,
			Rating:  "Critical",
		},
	}
	finding.SetDefaults()

	assert.NotEqual(t, uuid.Nil, finding.ID)
	assert.NotEmpty(t, finding.Title)
	assert.NotEmpty(t, finding.Description)
	assert.True(t, IsValidSeverity(finding.Severity))
	assert.True(t, IsValidConfidence(finding.Confidence))
	assert.True(t, IsValidDomain(finding.Domain))
	assert.False(t, finding.Timestamp.IsZero())
	assert.NotNil(t, finding.CVSS)
}

func TestResourceUsage_Validation(t *testing.T) {
	usage := &ResourceUsage{
		CPUTime:    100 * time.Millisecond,
		Memory:     1024 * 1024, // 1MB
		NetworkIn:  512,
		NetworkOut: 256,
		APICalls:   10,
		MaxMemory:  2 * 1024 * 1024, // 2MB
		Goroutines: 5,
	}

	assert.True(t, usage.CPUTime > 0)
	assert.True(t, usage.Memory > 0)
	assert.True(t, usage.NetworkIn >= 0)
	assert.True(t, usage.NetworkOut >= 0)
	assert.True(t, usage.APICalls >= 0)
	assert.True(t, usage.MaxMemory >= usage.Memory)
	assert.True(t, usage.Goroutines > 0)
}

func TestCVSSScore_Validation(t *testing.T) {
	score := &CVSSScore{
		Version: "3.1",
		Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Score:   9.8,
		Rating:  "Critical",
	}

	assert.NotEmpty(t, score.Version)
	assert.NotEmpty(t, score.Vector)
	assert.True(t, score.Score >= 0.0 && score.Score <= 10.0)
	assert.NotEmpty(t, score.Rating)
}

// Benchmark tests
func BenchmarkPluginInfo_SetDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		info := &PluginInfo{}
		info.SetDefaults()
	}
}

func BenchmarkAssessRequest_SetDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		request := &AssessRequest{}
		request.SetDefaults()
	}
}

func BenchmarkFinding_SetDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		finding := &Finding{}
		finding.SetDefaults()
	}
}

func BenchmarkIsValidDomain(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsValidDomain(DomainInterface)
	}
}

func BenchmarkIsValidSeverity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsValidSeverity(SeverityHigh)
	}
}
