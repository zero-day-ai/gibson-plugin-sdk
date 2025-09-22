package models

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResult_Ok(t *testing.T) {
	result := Ok("test value")

	assert.True(t, result.IsOk())
	assert.False(t, result.IsErr())
	assert.Equal(t, "test value", result.Unwrap())
	assert.Nil(t, result.Error())

	value, err := result.Value()
	assert.Equal(t, "test value", value)
	assert.Nil(t, err)
}

func TestResult_Err(t *testing.T) {
	testErr := errors.New("test error")
	result := Err[string](testErr)

	assert.False(t, result.IsOk())
	assert.True(t, result.IsErr())
	assert.Equal(t, testErr, result.Error())

	value, err := result.Value()
	assert.Equal(t, "", value) // zero value for string
	assert.Equal(t, testErr, err)
}

func TestResult_UnwrapOr(t *testing.T) {
	// Test with successful result
	okResult := Ok("success")
	assert.Equal(t, "success", okResult.UnwrapOr("default"))

	// Test with error result
	errResult := Err[string](errors.New("error"))
	assert.Equal(t, "default", errResult.UnwrapOr("default"))
}

func TestResult_UnwrapPanic(t *testing.T) {
	errResult := Err[string](errors.New("test error"))

	assert.Panics(t, func() {
		errResult.Unwrap()
	})
}

func TestResult_WithDifferentTypes(t *testing.T) {
	// Test with int
	intResult := Ok(42)
	assert.True(t, intResult.IsOk())
	assert.Equal(t, 42, intResult.Unwrap())

	// Test with struct
	type TestStruct struct {
		Name string
		Age  int
	}
	structResult := Ok(TestStruct{Name: "John", Age: 30})
	assert.True(t, structResult.IsOk())
	assert.Equal(t, TestStruct{Name: "John", Age: 30}, structResult.Unwrap())

	// Test with pointer
	testValue := "test"
	ptrResult := Ok(&testValue)
	assert.True(t, ptrResult.IsOk())
	assert.Equal(t, &testValue, ptrResult.Unwrap())
}
