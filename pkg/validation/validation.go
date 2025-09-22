package validation

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
)

// ValidationError represents a validation error with context
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Error implements the error interface
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidationResult contains the result of validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

// AddError adds a validation error
func (r *ValidationResult) AddError(field, message, code string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// HasErrors returns true if there are validation errors
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// GetErrorMessages returns all error messages
func (r *ValidationResult) GetErrorMessages() []string {
	messages := make([]string, len(r.Errors))
	for i, err := range r.Errors {
		messages[i] = err.Message
	}
	return messages
}

// Validator provides validation utilities for plugin data
type Validator struct {
	strictMode bool
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{strictMode: false}
}

// WithStrictMode enables strict validation mode
func (v *Validator) WithStrictMode(strict bool) *Validator {
	v.strictMode = strict
	return v
}

// ValidatePluginInfo validates plugin information
func (v *Validator) ValidatePluginInfo(info *plugin.PluginInfo) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if info == nil {
		result.AddError("plugin_info", "plugin info cannot be nil", "PLUGIN_INFO_NIL")
		return result
	}

	// Validate name
	if strings.TrimSpace(info.Name) == "" {
		result.AddError("name", "plugin name cannot be empty", "NAME_EMPTY")
	} else if !isValidPluginName(info.Name) {
		result.AddError("name", "plugin name contains invalid characters", "NAME_INVALID")
	}

	// Validate version
	if strings.TrimSpace(info.Version) == "" {
		result.AddError("version", "plugin version cannot be empty", "VERSION_EMPTY")
	} else if !isValidSemVer(info.Version) {
		result.AddError("version", "plugin version must be valid semantic version", "VERSION_INVALID")
	}

	// Validate description
	if strings.TrimSpace(info.Description) == "" && v.strictMode {
		result.AddError("description", "plugin description should not be empty", "DESCRIPTION_EMPTY")
	}

	// Validate author
	if strings.TrimSpace(info.Author) == "" && v.strictMode {
		result.AddError("author", "plugin author should not be empty", "AUTHOR_EMPTY")
	}

	// Validate domain
	if !plugin.IsValidDomain(info.Domain) {
		result.AddError("domain", "invalid security domain", "DOMAIN_INVALID")
	}

	// Validate supported payload types
	if len(info.SupportedPayloadTypes) == 0 && v.strictMode {
		result.AddError("supported_payload_types", "plugin should support at least one payload type", "PAYLOAD_TYPES_EMPTY")
	}

	for i, payloadType := range info.SupportedPayloadTypes {
		if !isValidPayloadType(payloadType) {
			result.AddError(fmt.Sprintf("supported_payload_types[%d]", i), "invalid payload type", "PAYLOAD_TYPE_INVALID")
		}
	}

	// Validate capabilities
	if info.Capabilities != nil {
		v.validateCapabilities(info.Capabilities, result)
	}

	return result
}

// ValidateTarget validates assessment target
func (v *Validator) ValidateTarget(target *plugin.Target) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if target == nil {
		result.AddError("target", "target cannot be nil", "TARGET_NIL")
		return result
	}

	// Validate ID
	if strings.TrimSpace(target.ID) == "" {
		result.AddError("id", "target ID cannot be empty", "ID_EMPTY")
	} else if !isValidID(target.ID) {
		result.AddError("id", "target ID contains invalid characters", "ID_INVALID")
	}

	// Validate name
	if strings.TrimSpace(target.Name) == "" {
		result.AddError("name", "target name cannot be empty", "NAME_EMPTY")
	}

	// Validate type
	if strings.TrimSpace(target.Type) == "" {
		result.AddError("type", "target type cannot be empty", "TYPE_EMPTY")
	}

	// Validate endpoint if provided
	if target.Endpoint != "" {
		if !isValidURL(target.Endpoint) {
			result.AddError("endpoint", "target endpoint must be a valid URL", "ENDPOINT_INVALID")
		}
	}

	// Validate credentials if provided
	if target.Credentials != nil {
		v.validateCredentials(target.Credentials, result)
	}

	return result
}

// ValidateAssessmentConfig validates assessment configuration
func (v *Validator) ValidateAssessmentConfig(config *plugin.AssessmentConfig) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if config == nil {
		result.AddError("config", "assessment config cannot be nil", "CONFIG_NIL")
		return result
	}

	// Validate domain
	if !plugin.IsValidDomain(config.Domain) {
		result.AddError("domain", "invalid security domain", "DOMAIN_INVALID")
	}

	// Validate payload types
	if len(config.PayloadTypes) == 0 && v.strictMode {
		result.AddError("payload_types", "at least one payload type should be specified", "PAYLOAD_TYPES_EMPTY")
	}

	for i, payloadType := range config.PayloadTypes {
		if !isValidPayloadType(payloadType) {
			result.AddError(fmt.Sprintf("payload_types[%d]", i), "invalid payload type", "PAYLOAD_TYPE_INVALID")
		}
	}

	// Validate max findings
	if config.MaxFindings < 0 {
		result.AddError("max_findings", "max findings cannot be negative", "MAX_FINDINGS_NEGATIVE")
	} else if config.MaxFindings > 10000 && v.strictMode {
		result.AddError("max_findings", "max findings seems too high (>10000)", "MAX_FINDINGS_HIGH")
	}

	// Validate timeout
	if config.TimeoutSeconds < 0 {
		result.AddError("timeout_seconds", "timeout cannot be negative", "TIMEOUT_NEGATIVE")
	} else if config.TimeoutSeconds > 3600 && v.strictMode {
		result.AddError("timeout_seconds", "timeout seems too high (>1 hour)", "TIMEOUT_HIGH")
	}

	return result
}

// ValidateFinding validates security finding
func (v *Validator) ValidateFinding(finding *plugin.Finding) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if finding == nil {
		result.AddError("finding", "finding cannot be nil", "FINDING_NIL")
		return result
	}

	// Validate ID
	if strings.TrimSpace(finding.ID) == "" {
		result.AddError("id", "finding ID cannot be empty", "ID_EMPTY")
	}

	// Validate title
	if strings.TrimSpace(finding.Title) == "" {
		result.AddError("title", "finding title cannot be empty", "TITLE_EMPTY")
	}

	// Validate description
	if strings.TrimSpace(finding.Description) == "" {
		result.AddError("description", "finding description cannot be empty", "DESCRIPTION_EMPTY")
	}

	// Validate severity
	if !isValidSeverity(finding.Severity) {
		result.AddError("severity", "invalid severity level", "SEVERITY_INVALID")
	}

	// Validate domain
	if !plugin.IsValidDomain(finding.Domain) {
		result.AddError("domain", "invalid security domain", "DOMAIN_INVALID")
	}

	// Validate payload type
	if !isValidPayloadType(finding.PayloadType) {
		result.AddError("payload_type", "invalid payload type", "PAYLOAD_TYPE_INVALID")
	}

	// Validate evidence if provided
	if finding.Evidence != nil {
		v.validateEvidence(finding.Evidence, result)
	}

	// Validate remediation if provided
	if finding.Remediation != nil {
		v.validateRemediation(finding.Remediation, result)
	}

	return result
}

// ValidateAssessRequest validates assessment request
func (v *Validator) ValidateAssessRequest(request *plugin.AssessRequest) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if request == nil {
		result.AddError("request", "assessment request cannot be nil", "REQUEST_NIL")
		return result
	}

	// Validate request ID
	if strings.TrimSpace(request.RequestID) == "" {
		result.AddError("request_id", "request ID cannot be empty", "REQUEST_ID_EMPTY")
	}

	// Validate target
	if request.Target == nil {
		result.AddError("target", "target cannot be nil", "TARGET_NIL")
	} else {
		targetResult := v.ValidateTarget(request.Target)
		for _, err := range targetResult.Errors {
			result.AddError("target."+err.Field, err.Message, err.Code)
		}
	}

	// Validate config
	if request.Config == nil {
		result.AddError("config", "assessment config cannot be nil", "CONFIG_NIL")
	} else {
		configResult := v.ValidateAssessmentConfig(request.Config)
		for _, err := range configResult.Errors {
			result.AddError("config."+err.Field, err.Message, err.Code)
		}
	}

	return result
}

// validateCapabilities validates plugin capabilities
func (v *Validator) validateCapabilities(capabilities *plugin.PluginCapabilities, result *ValidationResult) {
	if capabilities.MaxConcurrentRequests < 0 {
		result.AddError("capabilities.max_concurrent_requests", "max concurrent requests cannot be negative", "MAX_CONCURRENT_NEGATIVE")
	} else if capabilities.MaxConcurrentRequests > 1000 && v.strictMode {
		result.AddError("capabilities.max_concurrent_requests", "max concurrent requests seems too high (>1000)", "MAX_CONCURRENT_HIGH")
	}

	if capabilities.TimeoutSeconds < 0 {
		result.AddError("capabilities.timeout_seconds", "timeout cannot be negative", "TIMEOUT_NEGATIVE")
	} else if capabilities.TimeoutSeconds > 3600 && v.strictMode {
		result.AddError("capabilities.timeout_seconds", "timeout seems too high (>1 hour)", "TIMEOUT_HIGH")
	}
}

// validateCredentials validates target credentials
func (v *Validator) validateCredentials(credentials *plugin.Credentials, result *ValidationResult) {
	if strings.TrimSpace(credentials.Type) == "" {
		result.AddError("credentials.type", "credentials type cannot be empty", "CREDENTIALS_TYPE_EMPTY")
	}

	if len(credentials.Data) == 0 {
		result.AddError("credentials.data", "credentials data cannot be empty", "CREDENTIALS_DATA_EMPTY")
	}

	// Check for potentially unsafe credential storage
	if !credentials.Encrypted && v.strictMode {
		for key, value := range credentials.Data {
			if containsSensitiveKeywords(key) || containsSensitiveKeywords(value) {
				result.AddError("credentials.data", "sensitive credentials should be encrypted", "CREDENTIALS_UNENCRYPTED")
				break
			}
		}
	}
}

// validateEvidence validates finding evidence
func (v *Validator) validateEvidence(evidence *plugin.Evidence, result *ValidationResult) {
	if strings.TrimSpace(evidence.Type) == "" {
		result.AddError("evidence.type", "evidence type cannot be empty", "EVIDENCE_TYPE_EMPTY")
	}

	if strings.TrimSpace(evidence.Data) == "" {
		result.AddError("evidence.data", "evidence data cannot be empty", "EVIDENCE_DATA_EMPTY")
	}
}

// validateRemediation validates finding remediation
func (v *Validator) validateRemediation(remediation *plugin.Remediation, result *ValidationResult) {
	if strings.TrimSpace(remediation.Description) == "" && v.strictMode {
		result.AddError("remediation.description", "remediation description should not be empty", "REMEDIATION_DESCRIPTION_EMPTY")
	}

	if len(remediation.Steps) == 0 && v.strictMode {
		result.AddError("remediation.steps", "remediation steps should not be empty", "REMEDIATION_STEPS_EMPTY")
	}
}

// Helper validation functions

// isValidPluginName checks if plugin name is valid
func isValidPluginName(name string) bool {
	// Plugin name should contain only alphanumeric, dash, underscore
	re := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return re.MatchString(name) && len(name) <= 100
}

// isValidSemVer checks if version follows semantic versioning
func isValidSemVer(version string) bool {
	// Simple semantic version check (major.minor.patch)
	re := regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[a-zA-Z0-9-]+)?(\+[a-zA-Z0-9-]+)?$`)
	return re.MatchString(version)
}

// isValidID checks if ID is valid
func isValidID(id string) bool {
	// ID should contain only alphanumeric, dash, underscore
	re := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return re.MatchString(id) && len(id) <= 100
}

// isValidURL checks if URL is valid
func isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// isValidPayloadType checks if payload type is valid
func isValidPayloadType(payloadType plugin.PayloadType) bool {
	switch payloadType {
	case plugin.PayloadTypePrompt, plugin.PayloadTypeQuery, plugin.PayloadTypeInput,
		plugin.PayloadTypeCode, plugin.PayloadTypeData, plugin.PayloadTypeScript:
		return true
	default:
		return false
	}
}

// isValidSeverity checks if severity level is valid
func isValidSeverity(severity plugin.SeverityLevel) bool {
	switch severity {
	case plugin.SeverityInfo, plugin.SeverityLow, plugin.SeverityMedium,
		plugin.SeverityHigh, plugin.SeverityCritical:
		return true
	default:
		return false
	}
}

// containsSensitiveKeywords checks if text contains sensitive keywords
func containsSensitiveKeywords(text string) bool {
	sensitiveKeywords := []string{
		"password", "passwd", "pwd", "secret", "key", "token", "auth",
		"credential", "private", "confidential", "api_key", "access_token",
	}

	textLower := strings.ToLower(text)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(textLower, keyword) {
			return true
		}
	}
	return false
}

// Security validation functions

// ValidatePayload validates security payload for potential threats
func (v *Validator) ValidatePayload(payload string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if len(payload) > 100000 { // 100KB limit
		result.AddError("payload", "payload size exceeds maximum limit", "PAYLOAD_TOO_LARGE")
	}

	// Check for potentially malicious patterns
	if containsSQLInjectionPatterns(payload) {
		result.AddError("payload", "payload contains potential SQL injection patterns", "PAYLOAD_SQL_INJECTION")
	}

	if containsXSSPatterns(payload) {
		result.AddError("payload", "payload contains potential XSS patterns", "PAYLOAD_XSS")
	}

	if containsCommandInjectionPatterns(payload) {
		result.AddError("payload", "payload contains potential command injection patterns", "PAYLOAD_COMMAND_INJECTION")
	}

	return result
}

// containsSQLInjectionPatterns checks for SQL injection patterns
func containsSQLInjectionPatterns(payload string) bool {
	sqlPatterns := []string{
		"union select", "drop table", "delete from", "insert into",
		"update set", "exec(", "execute(", "sp_", "xp_", "' or '1'='1",
		"' or 1=1", "'; drop", "'; exec", "union all select",
	}

	payloadLower := strings.ToLower(payload)
	for _, pattern := range sqlPatterns {
		if strings.Contains(payloadLower, pattern) {
			return true
		}
	}
	return false
}

// containsXSSPatterns checks for XSS patterns
func containsXSSPatterns(payload string) bool {
	xssPatterns := []string{
		"<script", "</script", "javascript:", "on load=", "on error=",
		"on click=", "on focus=", "on blur=", "eval(", "alert(",
		"document.cookie", "window.location", "innerHTML",
	}

	payloadLower := strings.ToLower(payload)
	for _, pattern := range xssPatterns {
		if strings.Contains(payloadLower, pattern) {
			return true
		}
	}
	return false
}

// containsCommandInjectionPatterns checks for command injection patterns
func containsCommandInjectionPatterns(payload string) bool {
	cmdPatterns := []string{
		"; cat", "; ls", "; rm", "; chmod", "; sudo", "; su",
		"&& cat", "|| cat", "| cat", "`cat", "$(cat", "${cat",
		"; wget", "; curl", "; nc", "; netcat", "; bash", "; sh",
	}

	payloadLower := strings.ToLower(payload)
	for _, pattern := range cmdPatterns {
		if strings.Contains(payloadLower, pattern) {
			return true
		}
	}
	return false
}

// SanitizeString sanitizes input string for safe processing
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Normalize unicode
	input = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return -1 // Remove control characters
		}
		return r
	}, input)

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}

// ValidateStringLength validates string length constraints
func ValidateStringLength(value string, minLen, maxLen int, fieldName string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	length := len(value)
	if length < minLen {
		result.AddError(fieldName, fmt.Sprintf("must be at least %d characters", minLen), "LENGTH_TOO_SHORT")
	}
	if length > maxLen {
		result.AddError(fieldName, fmt.Sprintf("must be no more than %d characters", maxLen), "LENGTH_TOO_LONG")
	}

	return result
}
