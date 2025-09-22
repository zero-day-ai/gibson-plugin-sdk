// Package plugin defines error types for Gibson Framework security plugins
package plugin

import (
	"errors"
	"fmt"
)

// Common plugin errors
var (
	// ErrPluginNotInitialized indicates the plugin has not been properly initialized
	ErrPluginNotInitialized = errors.New("plugin not initialized")

	// ErrInvalidConfig indicates the plugin configuration is invalid
	ErrInvalidConfig = errors.New("invalid plugin configuration")

	// ErrTargetNotSupported indicates the target type is not supported by the plugin
	ErrTargetNotSupported = errors.New("target type not supported")

	// ErrExecutionTimeout indicates the plugin execution timed out
	ErrExecutionTimeout = errors.New("plugin execution timeout")

	// ErrPluginUnhealthy indicates the plugin is in an unhealthy state
	ErrPluginUnhealthy = errors.New("plugin is unhealthy")

	// ErrInvalidRequest indicates the assessment request is invalid
	ErrInvalidRequest = errors.New("invalid assessment request")

	// ErrResourceLimitExceeded indicates a resource limit was exceeded
	ErrResourceLimitExceeded = errors.New("resource limit exceeded")

	// ErrPluginPanic indicates the plugin panicked during execution
	ErrPluginPanic = errors.New("plugin panic during execution")

	// ErrStreamingNotSupported indicates streaming is not supported
	ErrStreamingNotSupported = errors.New("streaming not supported")

	// ErrBatchNotSupported indicates batch processing is not supported
	ErrBatchNotSupported = errors.New("batch processing not supported")
)

// PluginError represents a structured error from plugin execution
type PluginError struct {
	Type      ErrorType              `json:"type"`
	Message   string                 `json:"message"`
	Code      string                 `json:"code"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Cause     error                  `json:"-"` // Original error, not serialized
	Timestamp string                 `json:"timestamp"`
	PluginID  string                 `json:"plugin_id"`
}

// ErrorType represents the category of plugin error
type ErrorType string

const (
	ErrorTypeConfiguration  ErrorType = "configuration"
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeExecution      ErrorType = "execution"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeResource       ErrorType = "resource"
	ErrorTypeNetwork        ErrorType = "network"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeInternal       ErrorType = "internal"
	ErrorTypeExternal       ErrorType = "external"
)

// Error implements the error interface
func (pe *PluginError) Error() string {
	if pe.Code != "" {
		return fmt.Sprintf("[%s:%s] %s", pe.Type, pe.Code, pe.Message)
	}
	return fmt.Sprintf("[%s] %s", pe.Type, pe.Message)
}

// Unwrap returns the underlying error
func (pe *PluginError) Unwrap() error {
	return pe.Cause
}

// Is checks if the error matches the target error
func (pe *PluginError) Is(target error) bool {
	if pe.Cause != nil {
		return errors.Is(pe.Cause, target)
	}
	return false
}

// NewPluginError creates a new plugin error
func NewPluginError(errorType ErrorType, message string) *PluginError {
	return &PluginError{
		Type:    errorType,
		Message: message,
	}
}

// NewPluginErrorWithCode creates a new plugin error with a code
func NewPluginErrorWithCode(errorType ErrorType, code, message string) *PluginError {
	return &PluginError{
		Type:    errorType,
		Code:    code,
		Message: message,
	}
}

// NewPluginErrorWithCause creates a new plugin error wrapping another error
func NewPluginErrorWithCause(errorType ErrorType, message string, cause error) *PluginError {
	return &PluginError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// ConfigurationError creates a configuration error
func ConfigurationError(message string) *PluginError {
	return NewPluginError(ErrorTypeConfiguration, message)
}

// ValidationError creates a validation error
func ValidationError(message string) *PluginError {
	return NewPluginError(ErrorTypeValidation, message)
}

// ExecutionError creates an execution error
func ExecutionError(message string) *PluginError {
	return NewPluginError(ErrorTypeExecution, message)
}

// TimeoutError creates a timeout error
func TimeoutError(message string) *PluginError {
	return NewPluginError(ErrorTypeTimeout, message)
}

// ResourceError creates a resource error
func ResourceError(message string) *PluginError {
	return NewPluginError(ErrorTypeResource, message)
}

// NetworkError creates a network error
func NetworkError(message string) *PluginError {
	return NewPluginError(ErrorTypeNetwork, message)
}

// AuthenticationError creates an authentication error
func AuthenticationError(message string) *PluginError {
	return NewPluginError(ErrorTypeAuthentication, message)
}

// AuthorizationError creates an authorization error
func AuthorizationError(message string) *PluginError {
	return NewPluginError(ErrorTypeAuthorization, message)
}

// InternalError creates an internal error
func InternalError(message string) *PluginError {
	return NewPluginError(ErrorTypeInternal, message)
}

// ExternalError creates an external error
func ExternalError(message string) *PluginError {
	return NewPluginError(ErrorTypeExternal, message)
}

// WrapError wraps an existing error as a plugin error
func WrapError(errorType ErrorType, message string, err error) *PluginError {
	return NewPluginErrorWithCause(errorType, message, err)
}
