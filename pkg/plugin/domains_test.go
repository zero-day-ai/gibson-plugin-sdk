package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAllDomains(t *testing.T) {
	domains := GetAllDomains()
	assert.Len(t, domains, 6)

	expectedDomains := []SecurityDomain{
		DomainModel,
		DomainData,
		DomainInterface,
		DomainInfrastructure,
		DomainOutput,
		DomainProcess,
	}

	for _, expected := range expectedDomains {
		assert.Contains(t, domains, expected)
	}
}

func TestGetAllPayloadCategories(t *testing.T) {
	categories := GetAllPayloadCategories()
	assert.Len(t, categories, 8)

	expectedCategories := []PayloadCategory{
		PayloadCategoryPrompt,
		PayloadCategoryQuery,
		PayloadCategoryInput,
		PayloadCategoryCode,
		PayloadCategoryData,
		PayloadCategoryScript,
		PayloadCategoryConfig,
		PayloadCategoryNetwork,
	}

	for _, expected := range expectedCategories {
		assert.Contains(t, categories, expected)
	}
}

func TestGetAllAttackVectors(t *testing.T) {
	vectors := GetAllAttackVectors()
	assert.Len(t, vectors, 6)

	expectedVectors := []AttackVector{
		VectorDirect,
		VectorIndirect,
		VectorSocial,
		VectorPhysical,
		VectorNetwork,
		VectorApplication,
	}

	for _, expected := range expectedVectors {
		assert.Contains(t, vectors, expected)
	}
}

func TestGetAllThreatLevels(t *testing.T) {
	levels := GetAllThreatLevels()
	assert.Len(t, levels, 5)

	expectedLevels := []ThreatLevel{
		ThreatLevelCritical,
		ThreatLevelHigh,
		ThreatLevelMedium,
		ThreatLevelLow,
		ThreatLevelInfo,
	}

	for _, expected := range expectedLevels {
		assert.Contains(t, levels, expected)
	}
}

func TestIsValidDomain(t *testing.T) {
	validDomains := []SecurityDomain{
		DomainModel,
		DomainData,
		DomainInterface,
		DomainInfrastructure,
		DomainOutput,
		DomainProcess,
	}

	for _, domain := range validDomains {
		assert.True(t, IsValidDomain(domain), "Domain %s should be valid", domain)
	}

	assert.False(t, IsValidDomain("invalid-domain"))
	assert.False(t, IsValidDomain(""))
}

func TestIsValidPayloadCategory(t *testing.T) {
	validCategories := []PayloadCategory{
		PayloadCategoryPrompt,
		PayloadCategoryQuery,
		PayloadCategoryInput,
		PayloadCategoryCode,
		PayloadCategoryData,
		PayloadCategoryScript,
		PayloadCategoryConfig,
		PayloadCategoryNetwork,
	}

	for _, category := range validCategories {
		assert.True(t, IsValidPayloadCategory(category), "Category %s should be valid", category)
	}

	assert.False(t, IsValidPayloadCategory("invalid-category"))
	assert.False(t, IsValidPayloadCategory(""))
}

func TestIsValidAttackVector(t *testing.T) {
	validVectors := []AttackVector{
		VectorDirect,
		VectorIndirect,
		VectorSocial,
		VectorPhysical,
		VectorNetwork,
		VectorApplication,
	}

	for _, vector := range validVectors {
		assert.True(t, IsValidAttackVector(vector), "Vector %s should be valid", vector)
	}

	assert.False(t, IsValidAttackVector("invalid-vector"))
	assert.False(t, IsValidAttackVector(""))
}

func TestIsValidThreatLevel(t *testing.T) {
	validLevels := []ThreatLevel{
		ThreatLevelCritical,
		ThreatLevelHigh,
		ThreatLevelMedium,
		ThreatLevelLow,
		ThreatLevelInfo,
	}

	for _, level := range validLevels {
		assert.True(t, IsValidThreatLevel(level), "Level %s should be valid", level)
	}

	assert.False(t, IsValidThreatLevel("invalid-level"))
	assert.False(t, IsValidThreatLevel(""))
}

func TestGetDomainDescription(t *testing.T) {
	tests := []struct {
		domain      SecurityDomain
		shouldMatch string
	}{
		{DomainModel, "AI/ML model-specific"},
		{DomainData, "Data-centric"},
		{DomainInterface, "Prompt and interface"},
		{DomainInfrastructure, "System and infrastructure"},
		{DomainOutput, "Output and response"},
		{DomainProcess, "Operational and governance"},
		{"invalid", "Unknown security domain"},
	}

	for _, test := range tests {
		description := GetDomainDescription(test.domain)
		assert.Contains(t, description, test.shouldMatch)
	}
}

func TestGetCategoryDescription(t *testing.T) {
	tests := []struct {
		category    PayloadCategory
		shouldMatch string
	}{
		{PayloadCategoryPrompt, "Prompt-based"},
		{PayloadCategoryQuery, "Query-based"},
		{PayloadCategoryInput, "General input-based"},
		{PayloadCategoryCode, "Code-based"},
		{PayloadCategoryData, "Data-based"},
		{PayloadCategoryScript, "Script-based"},
		{PayloadCategoryConfig, "Configuration-based"},
		{PayloadCategoryNetwork, "Network-based"},
		{"invalid", "Unknown payload category"},
	}

	for _, test := range tests {
		description := GetCategoryDescription(test.category)
		assert.Contains(t, description, test.shouldMatch)
	}
}

func TestGetCompatibleCategories(t *testing.T) {
	tests := []struct {
		domain             SecurityDomain
		expectedCategories []PayloadCategory
	}{
		{
			DomainModel,
			[]PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput, PayloadCategoryData},
		},
		{
			DomainInterface,
			[]PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput, PayloadCategoryCode},
		},
		{
			DomainInfrastructure,
			[]PayloadCategory{PayloadCategoryNetwork, PayloadCategoryConfig, PayloadCategoryScript},
		},
	}

	for _, test := range tests {
		categories := GetCompatibleCategories(test.domain)
		assert.Equal(t, len(test.expectedCategories), len(categories))
		for _, expected := range test.expectedCategories {
			assert.Contains(t, categories, expected)
		}
	}

	// Test invalid domain
	categories := GetCompatibleCategories("invalid")
	assert.Empty(t, categories)
}

func TestGetCompatibleVectors(t *testing.T) {
	tests := []struct {
		domain          SecurityDomain
		expectedVectors []AttackVector
	}{
		{
			DomainModel,
			[]AttackVector{VectorDirect, VectorIndirect, VectorApplication},
		},
		{
			DomainInterface,
			[]AttackVector{VectorDirect, VectorSocial, VectorApplication},
		},
		{
			DomainInfrastructure,
			[]AttackVector{VectorNetwork, VectorPhysical, VectorApplication},
		},
	}

	for _, test := range tests {
		vectors := GetCompatibleVectors(test.domain)
		assert.Equal(t, len(test.expectedVectors), len(vectors))
		for _, expected := range test.expectedVectors {
			assert.Contains(t, vectors, expected)
		}
	}

	// Test invalid domain
	vectors := GetCompatibleVectors("invalid")
	assert.Empty(t, vectors)
}

func TestParseDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected SecurityDomain
		hasError bool
	}{
		{"model", DomainModel, false},
		{"MODEL", DomainModel, false},
		{"  data  ", DomainData, false},
		{"interface", DomainInterface, false},
		{"infrastructure", DomainInfrastructure, false},
		{"output", DomainOutput, false},
		{"process", DomainProcess, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		result, err := ParseDomain(test.input)
		if test.hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		}
	}
}

func TestParsePayloadCategory(t *testing.T) {
	tests := []struct {
		input    string
		expected PayloadCategory
		hasError bool
	}{
		{"prompt", PayloadCategoryPrompt, false},
		{"QUERY", PayloadCategoryQuery, false},
		{"  input  ", PayloadCategoryInput, false},
		{"code", PayloadCategoryCode, false},
		{"data", PayloadCategoryData, false},
		{"script", PayloadCategoryScript, false},
		{"config", PayloadCategoryConfig, false},
		{"network", PayloadCategoryNetwork, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		result, err := ParsePayloadCategory(test.input)
		if test.hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		}
	}
}

func TestParseAttackVector(t *testing.T) {
	tests := []struct {
		input    string
		expected AttackVector
		hasError bool
	}{
		{"direct", VectorDirect, false},
		{"INDIRECT", VectorIndirect, false},
		{"  social  ", VectorSocial, false},
		{"physical", VectorPhysical, false},
		{"network", VectorNetwork, false},
		{"application", VectorApplication, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		result, err := ParseAttackVector(test.input)
		if test.hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		}
	}
}

func TestParseThreatLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatLevel
		hasError bool
	}{
		{"critical", ThreatLevelCritical, false},
		{"HIGH", ThreatLevelHigh, false},
		{"  medium  ", ThreatLevelMedium, false},
		{"low", ThreatLevelLow, false},
		{"info", ThreatLevelInfo, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		result, err := ParseThreatLevel(test.input)
		if test.hasError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		}
	}
}

func TestGetDomainCapabilities(t *testing.T) {
	capabilities := GetDomainCapabilities()

	// Check that we have capabilities for key domains
	assert.NotEmpty(t, capabilities[DomainModel])
	assert.NotEmpty(t, capabilities[DomainInterface])
	assert.NotEmpty(t, capabilities[DomainInfrastructure])
	assert.NotEmpty(t, capabilities[DomainData])
	assert.NotEmpty(t, capabilities[DomainOutput])
	assert.NotEmpty(t, capabilities[DomainProcess])

	// Check that capabilities have required fields
	for domain, domainCapabilities := range capabilities {
		for _, capability := range domainCapabilities {
			assert.Equal(t, domain, capability.Domain)
			assert.NotEmpty(t, capability.Name)
			assert.NotEmpty(t, capability.Description)
			assert.NotEmpty(t, capability.Categories)
			assert.NotEmpty(t, capability.Vectors)
			assert.NotEmpty(t, capability.Examples)
		}
	}
}

func TestGetCapabilitiesForDomain(t *testing.T) {
	modelCapabilities := GetCapabilitiesForDomain(DomainModel)
	assert.NotEmpty(t, modelCapabilities)

	for _, capability := range modelCapabilities {
		assert.Equal(t, DomainModel, capability.Domain)
	}

	// Test invalid domain
	invalidCapabilities := GetCapabilitiesForDomain("invalid")
	assert.Empty(t, invalidCapabilities)
}

func TestFindCapability(t *testing.T) {
	// Find existing capability
	capability, found := FindCapability("adversarial-attacks")
	assert.True(t, found)
	require.NotNil(t, capability)
	assert.Equal(t, "adversarial-attacks", capability.Name)
	assert.Equal(t, DomainModel, capability.Domain)

	// Find non-existing capability
	capability, found = FindCapability("non-existing-capability")
	assert.False(t, found)
	assert.Nil(t, capability)
}
