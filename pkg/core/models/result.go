// Package models provides core model types for the Gibson Plugin SDK
package models

// Result represents a functional result type for error handling
// It follows the Gibson framework's Result[T] pattern for consistent error handling
type Result[T any] struct {
	value T
	err   error
}

// Ok creates a successful result
func Ok[T any](value T) Result[T] {
	return Result[T]{value: value, err: nil}
}

// Err creates an error result
func Err[T any](err error) Result[T] {
	var zero T
	return Result[T]{value: zero, err: err}
}

// IsOk returns true if the result contains a value
func (r Result[T]) IsOk() bool {
	return r.err == nil
}

// IsErr returns true if the result contains an error
func (r Result[T]) IsErr() bool {
	return r.err != nil
}

// Unwrap returns the value or panics if there's an error
func (r Result[T]) Unwrap() T {
	if r.err != nil {
		panic(r.err)
	}
	return r.value
}

// UnwrapOr returns the value or the provided default if there's an error
func (r Result[T]) UnwrapOr(defaultValue T) T {
	if r.err != nil {
		return defaultValue
	}
	return r.value
}

// Error returns the error or nil
func (r Result[T]) Error() error {
	return r.err
}

// Value returns the value and error separately
// This provides compatibility with traditional Go error handling patterns
func (r Result[T]) Value() (T, error) {
	return r.value, r.err
}
