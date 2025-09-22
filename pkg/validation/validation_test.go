package validation

import (
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestValidationError_Error(t *testing.T) {
	err := ValidationError{
		Field:   "test_field",
		Message: "test message",
		Code:    "TEST_CODE",
	}

	expected := "validation error in field 'test_field': test message"
	assert.Equal(t, expected, err.Error())
}

func TestValidationResult_AddError(t *testing.T) {
	result := &ValidationResult{Valid: true}

	result.AddError("field1", "message1", "CODE1")

	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, "field1", result.Errors[0].Field)
	assert.Equal(t, "message1", result.Errors[0].Message)
	assert.Equal(t, "CODE1", result.Errors[0].Code)
}

func TestValidationResult_HasErrors(t *testing.T) {
	result := &ValidationResult{Valid: true}
	assert.False(t, result.HasErrors())

	result.AddError("field", "message", "CODE")
	assert.True(t, result.HasErrors())
}

func TestValidationResult_GetErrorMessages(t *testing.T) {
	result := &ValidationResult{Valid: true}
	result.AddError("field1", "message1", "CODE1")
	result.AddError("field2", "message2", "CODE2")

	messages := result.GetErrorMessages()
	assert.Len(t, messages, 2)
	assert.Contains(t, messages, "message1")
	assert.Contains(t, messages, "message2")
}

func TestNewValidator(t *testing.T) {
	validator := NewValidator()
	assert.NotNil(t, validator)
	assert.False(t, validator.strictMode)
}

func TestValidator_WithStrictMode(t *testing.T) {
	validator := NewValidator().WithStrictMode(true)
	assert.True(t, validator.strictMode)

	validator = validator.WithStrictMode(false)
	assert.False(t, validator.strictMode)
}

func TestValidator_ValidatePluginInfo(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		info     *plugin.PluginInfo
		wantErr  bool
		errCodes []string
	}{
		{
			name:     "nil plugin info",
			info:     nil,
			wantErr:  true,
			errCodes: []string{"PLUGIN_INFO_NIL"},
		},
		{
			name: "valid plugin info",
			info: &plugin.PluginInfo{
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "Test plugin",
				Author:      "Test Author",
				Domain:      plugin.DomainInterface,
				SupportedPayloadTypes: []plugin.PayloadType{
					plugin.PayloadTypeInput,
				},
				Capabilities: &plugin.PluginCapabilities{
					MaxConcurrentRequests: 10,
					TimeoutSeconds:        30,
				},
			},
			wantErr: false,
		},
		{
			name: "empty name",
			info: &plugin.PluginInfo{
				Name:    "",
				Version: "1.0.0",
				Domain:  plugin.DomainInterface,
			},
			wantErr:  true,
			errCodes: []string{"NAME_EMPTY"},
		},
		{
			name: "invalid name characters",
			info: &plugin.PluginInfo{
				Name:    "test plugin!",
				Version: "1.0.0",
				Domain:  plugin.DomainInterface,
			},
			wantErr:  true,
			errCodes: []string{"NAME_INVALID"},
		},
		{
			name: "empty version",
			info: &plugin.PluginInfo{
				Name:    "test-plugin",
				Version: "",
				Domain:  plugin.DomainInterface,
			},
			wantErr:  true,
			errCodes: []string{"VERSION_EMPTY"},
		},
		{
			name: "invalid version format",
			info: &plugin.PluginInfo{
				Name:    "test-plugin",
				Version: "invalid-version",
				Domain:  plugin.DomainInterface,
			},
			wantErr:  true,
			errCodes: []string{"VERSION_INVALID"},
		},
		{
			name: "invalid domain",
			info: &plugin.PluginInfo{
				Name:    "test-plugin",
				Version: "1.0.0",
				Domain:  "invalid-domain",
			},
			wantErr:  true,
			errCodes: []string{"DOMAIN_INVALID"},
		},
		{
			name: "invalid payload type",
			info: &plugin.PluginInfo{
				Name:    "test-plugin",
				Version: "1.0.0",
				Domain:  plugin.DomainInterface,
				SupportedPayloadTypes: []plugin.PayloadType{
					"invalid-payload-type",
				},
			},
			wantErr:  true,
			errCodes: []string{"PAYLOAD_TYPE_INVALID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidatePluginInfo(tt.info)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidator_ValidateTarget(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		target   *plugin.Target
		wantErr  bool
		errCodes []string
	}{
		{
			name:     "nil target",
			target:   nil,
			wantErr:  true,
			errCodes: []string{"TARGET_NIL"},
		},
		{
			name: "valid target",
			target: &plugin.Target{
				ID:       "test-target",
				Name:     "Test Target",
				Type:     "api",
				Endpoint: "https://api.example.com",
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			target: &plugin.Target{
				Name: "Test Target",
				Type: "api",
			},
			wantErr:  true,
			errCodes: []string{"ID_EMPTY"},
		},
		{
			name: "invalid ID characters",
			target: &plugin.Target{
				ID:   "test target!",
				Name: "Test Target",
				Type: "api",
			},
			wantErr:  true,
			errCodes: []string{"ID_INVALID"},
		},
		{
			name: "empty name",
			target: &plugin.Target{
				ID:   "test-target",
				Name: "",
				Type: "api",
			},
			wantErr:  true,
			errCodes: []string{"NAME_EMPTY"},
		},
		{
			name: "empty type",
			target: &plugin.Target{
				ID:   "test-target",
				Name: "Test Target",
				Type: "",
			},
			wantErr:  true,
			errCodes: []string{"TYPE_EMPTY"},
		},
		{
			name: "invalid endpoint URL",
			target: &plugin.Target{
				ID:       "test-target",
				Name:     "Test Target",
				Type:     "api",
				Endpoint: "invalid-url",
			},
			wantErr:  true,
			errCodes: []string{"ENDPOINT_INVALID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateTarget(tt.target)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidator_ValidateAssessmentConfig(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		config   *plugin.AssessmentConfig
		wantErr  bool
		errCodes []string
	}{
		{
			name:     "nil config",
			config:   nil,
			wantErr:  true,
			errCodes: []string{"CONFIG_NIL"},
		},
		{
			name: "valid config",
			config: &plugin.AssessmentConfig{
				Domain: plugin.DomainInterface,
				PayloadTypes: []plugin.PayloadType{
					plugin.PayloadTypeInput,
				},
				MaxFindings:    100,
				TimeoutSeconds: 60,
			},
			wantErr: false,
		},
		{
			name: "invalid domain",
			config: &plugin.AssessmentConfig{
				Domain: "invalid-domain",
			},
			wantErr:  true,
			errCodes: []string{"DOMAIN_INVALID"},
		},
		{
			name: "negative max findings",
			config: &plugin.AssessmentConfig{
				Domain:      plugin.DomainInterface,
				MaxFindings: -1,
			},
			wantErr:  true,
			errCodes: []string{"MAX_FINDINGS_NEGATIVE"},
		},
		{
			name: "negative timeout",
			config: &plugin.AssessmentConfig{
				Domain:         plugin.DomainInterface,
				TimeoutSeconds: -1,
			},
			wantErr:  true,
			errCodes: []string{"TIMEOUT_NEGATIVE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateAssessmentConfig(tt.config)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidator_ValidateFinding(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		finding  *plugin.Finding
		wantErr  bool
		errCodes []string
	}{
		{
			name:     "nil finding",
			finding:  nil,
			wantErr:  true,
			errCodes: []string{"FINDING_NIL"},
		},
		{
			name: "valid finding",
			finding: &plugin.Finding{
				ID:           "test-finding",
				Title:        "Test Finding",
				Description:  "Test description",
				Severity:     plugin.SeverityHigh,
				Domain:       plugin.DomainInterface,
				PayloadType:  plugin.PayloadTypeInput,
				DiscoveredAt: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			finding: &plugin.Finding{
				Title:       "Test Finding",
				Description: "Test description",
			},
			wantErr:  true,
			errCodes: []string{"ID_EMPTY"},
		},
		{
			name: "empty title",
			finding: &plugin.Finding{
				ID:          "test-finding",
				Description: "Test description",
			},
			wantErr:  true,
			errCodes: []string{"TITLE_EMPTY"},
		},
		{
			name: "empty description",
			finding: &plugin.Finding{
				ID:    "test-finding",
				Title: "Test Finding",
			},
			wantErr:  true,
			errCodes: []string{"DESCRIPTION_EMPTY"},
		},
		{
			name: "invalid severity",
			finding: &plugin.Finding{
				ID:          "test-finding",
				Title:       "Test Finding",
				Description: "Test description",
				Severity:    "invalid-severity",
			},
			wantErr:  true,
			errCodes: []string{"SEVERITY_INVALID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateFinding(tt.finding)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidator_ValidateAssessRequest(t *testing.T) {
	validator := NewValidator()

	validTarget := &plugin.Target{
		ID:   "test-target",
		Name: "Test Target",
		Type: "api",
	}

	validConfig := &plugin.AssessmentConfig{
		Domain: plugin.DomainInterface,
		PayloadTypes: []plugin.PayloadType{
			plugin.PayloadTypeInput,
		},
	}

	tests := []struct {
		name     string
		request  *plugin.AssessRequest
		wantErr  bool
		errCodes []string
	}{
		{
			name:     "nil request",
			request:  nil,
			wantErr:  true,
			errCodes: []string{"REQUEST_NIL"},
		},
		{
			name: "valid request",
			request: &plugin.AssessRequest{
				RequestID: "test-request",
				Target:    validTarget,
				Config:    validConfig,
			},
			wantErr: false,
		},
		{
			name: "empty request ID",
			request: &plugin.AssessRequest{
				Target: validTarget,
				Config: validConfig,
			},
			wantErr:  true,
			errCodes: []string{"REQUEST_ID_EMPTY"},
		},
		{
			name: "nil target",
			request: &plugin.AssessRequest{
				RequestID: "test-request",
				Config:    validConfig,
			},
			wantErr:  true,
			errCodes: []string{"TARGET_NIL"},
		},
		{
			name: "nil config",
			request: &plugin.AssessRequest{
				RequestID: "test-request",
				Target:    validTarget,
			},
			wantErr:  true,
			errCodes: []string{"CONFIG_NIL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateAssessRequest(tt.request)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestValidator_ValidatePayload(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		payload  string
		wantErr  bool
		errCodes []string
	}{
		{
			name:    "safe payload",
			payload: "normal input text",
			wantErr: false,
		},
		{
			name:     "SQL injection payload",
			payload:  "'; DROP TABLE users; --",
			wantErr:  true,
			errCodes: []string{"PAYLOAD_SQL_INJECTION"},
		},
		{
			name:     "XSS payload",
			payload:  "<script>alert('xss')</script>",
			wantErr:  true,
			errCodes: []string{"PAYLOAD_XSS"},
		},
		{
			name:     "Command injection payload",
			payload:  "; cat /etc/passwd",
			wantErr:  true,
			errCodes: []string{"PAYLOAD_COMMAND_INJECTION"},
		},
		{
			name:     "oversized payload",
			payload:  string(make([]byte, 100001)), // 100KB + 1
			wantErr:  true,
			errCodes: []string{"PAYLOAD_TOO_LARGE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidatePayload(tt.payload)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestIsValidPluginName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid name", "test-plugin", true},
		{"valid with underscore", "test_plugin", true},
		{"valid with numbers", "test123", true},
		{"invalid with space", "test plugin", false},
		{"invalid with special chars", "test@plugin", false},
		{"empty", "", false},
		{"too long", string(make([]byte, 101)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPluginName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidSemVer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid version", "1.0.0", true},
		{"valid with v prefix", "v1.0.0", true},
		{"valid with prerelease", "1.0.0-alpha", true},
		{"valid with build", "1.0.0+build123", true},
		{"invalid format", "1.0", false},
		{"invalid characters", "1.0.a", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSemVer(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid HTTP URL", "http://example.com", true},
		{"valid HTTPS URL", "https://example.com", true},
		{"valid with path", "https://example.com/path", true},
		{"valid with query", "https://example.com?query=1", true},
		{"invalid no scheme", "example.com", false},
		{"invalid empty", "", false},
		{"invalid relative", "/path/to/resource", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal string", "hello world", "hello world"},
		{"with null bytes", "hello\x00world", "helloworld"},
		{"with control chars", "hello\x01\x02world", "helloworld"},
		{"with whitespace", "  hello world  ", "hello world"},
		{"with newlines", "hello\nworld", "hello\nworld"},
		{"with tabs", "hello\tworld", "hello\tworld"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		minLen    int
		maxLen    int
		fieldName string
		wantErr   bool
		errCodes  []string
	}{
		{
			name:      "valid length",
			value:     "hello",
			minLen:    3,
			maxLen:    10,
			fieldName: "test_field",
			wantErr:   false,
		},
		{
			name:      "too short",
			value:     "hi",
			minLen:    3,
			maxLen:    10,
			fieldName: "test_field",
			wantErr:   true,
			errCodes:  []string{"LENGTH_TOO_SHORT"},
		},
		{
			name:      "too long",
			value:     "this is too long",
			minLen:    3,
			maxLen:    10,
			fieldName: "test_field",
			wantErr:   true,
			errCodes:  []string{"LENGTH_TOO_LONG"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateStringLength(tt.value, tt.minLen, tt.maxLen, tt.fieldName)

			if tt.wantErr {
				assert.True(t, result.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range result.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, result.HasErrors())
				assert.True(t, result.Valid)
			}
		})
	}
}

func TestContainsSensitiveKeywords(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"no sensitive keywords", "normal text", false},
		{"contains password", "my password is secret", true},
		{"contains API key", "api_key=abc123", true},
		{"contains token", "access_token", true},
		{"case insensitive", "PASSWORD", true},
		{"partial match", "confidential info", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSensitiveKeywords(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateCapabilities(t *testing.T) {
	validator := NewValidator()
	result := &ValidationResult{Valid: true}

	// Test valid capabilities
	capabilities := &plugin.PluginCapabilities{
		MaxConcurrentRequests: 10,
		TimeoutSeconds:        30,
	}
	validator.validateCapabilities(capabilities, result)
	assert.False(t, result.HasErrors())

	// Test negative max concurrent requests
	result = &ValidationResult{Valid: true}
	capabilities.MaxConcurrentRequests = -1
	validator.validateCapabilities(capabilities, result)
	assert.True(t, result.HasErrors())
	assert.Equal(t, "MAX_CONCURRENT_NEGATIVE", result.Errors[0].Code)

	// Test negative timeout
	result = &ValidationResult{Valid: true}
	capabilities.MaxConcurrentRequests = 10
	capabilities.TimeoutSeconds = -1
	validator.validateCapabilities(capabilities, result)
	assert.True(t, result.HasErrors())
	assert.Equal(t, "TIMEOUT_NEGATIVE", result.Errors[0].Code)
}

func TestValidateCredentials(t *testing.T) {
	validator := NewValidator().WithStrictMode(true)
	result := &ValidationResult{Valid: true}

	// Test empty credentials type
	credentials := &plugin.Credentials{
		Type: "",
		Data: map[string]string{"key": "value"},
	}
	validator.validateCredentials(credentials, result)
	assert.True(t, result.HasErrors())

	// Test empty credentials data
	result = &ValidationResult{Valid: true}
	credentials.Type = "basic"
	credentials.Data = map[string]string{}
	validator.validateCredentials(credentials, result)
	assert.True(t, result.HasErrors())

	// Test unencrypted sensitive data
	result = &ValidationResult{Valid: true}
	credentials.Data = map[string]string{"password": "secret123"}
	credentials.Encrypted = false
	validator.validateCredentials(credentials, result)
	assert.True(t, result.HasErrors())
}

// Benchmark tests for performance validation
func BenchmarkValidatePluginInfo(b *testing.B) {
	validator := NewValidator()
	info := &plugin.PluginInfo{
		Name:        "test-plugin",
		Version:     "1.0.0",
		Description: "Test plugin",
		Author:      "Test Author",
		Domain:      plugin.DomainInterface,
		SupportedPayloadTypes: []plugin.PayloadType{
			plugin.PayloadTypeInput,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePluginInfo(info)
	}
}

func BenchmarkValidatePayload(b *testing.B) {
	validator := NewValidator()
	payload := "normal safe payload for testing"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePayload(payload)
	}
}

func BenchmarkSanitizeString(b *testing.B) {
	input := "hello\x00world\x01test\x02string"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SanitizeString(input)
	}
}
