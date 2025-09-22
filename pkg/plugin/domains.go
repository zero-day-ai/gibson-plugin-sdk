// Package plugin defines security domains and payload categories for Gibson Framework
package plugin

import (
	"fmt"
	"strings"
)

// SecurityDomain represents the six core security domains in Gibson Framework
type SecurityDomain string

const (
	// DomainModel covers AI/ML model-specific security assessments
	// This includes model poisoning, adversarial attacks, model extraction, etc.
	DomainModel SecurityDomain = "model"

	// DomainData covers data-centric security assessments
	// This includes data poisoning, privacy attacks, data leakage, etc.
	DomainData SecurityDomain = "data"

	// DomainInterface covers prompt and interface security assessments
	// This includes prompt injection, jailbreaking, input validation, etc.
	DomainInterface SecurityDomain = "interface"

	// DomainInfrastructure covers system and infrastructure security assessments
	// This includes container security, API security, network security, etc.
	DomainInfrastructure SecurityDomain = "infrastructure"

	// DomainOutput covers output and response security assessments
	// This includes content filtering, output validation, harmful content detection, etc.
	DomainOutput SecurityDomain = "output"

	// DomainProcess covers operational and governance security assessments
	// This includes compliance checks, audit trails, policy validation, etc.
	DomainProcess SecurityDomain = "process"
)

// PayloadCategory represents the category of security payloads
type PayloadCategory string

const (
	// PayloadCategoryPrompt covers prompt-based security payloads
	PayloadCategoryPrompt PayloadCategory = "prompt"

	// PayloadCategoryQuery covers query-based security payloads
	PayloadCategoryQuery PayloadCategory = "query"

	// PayloadCategoryInput covers general input-based security payloads
	PayloadCategoryInput PayloadCategory = "input"

	// PayloadCategoryCode covers code-based security payloads
	PayloadCategoryCode PayloadCategory = "code"

	// PayloadCategoryData covers data-based security payloads
	PayloadCategoryData PayloadCategory = "data"

	// PayloadCategoryScript covers script-based security payloads
	PayloadCategoryScript PayloadCategory = "script"

	// PayloadCategoryConfig covers configuration-based security payloads
	PayloadCategoryConfig PayloadCategory = "config"

	// PayloadCategoryNetwork covers network-based security payloads
	PayloadCategoryNetwork PayloadCategory = "network"
)

// AttackVector represents the method of attack execution
type AttackVector string

const (
	// VectorDirect represents direct attacks against the target
	VectorDirect AttackVector = "direct"

	// VectorIndirect represents indirect attacks through intermediaries
	VectorIndirect AttackVector = "indirect"

	// VectorSocial represents social engineering attacks
	VectorSocial AttackVector = "social"

	// VectorPhysical represents physical access attacks
	VectorPhysical AttackVector = "physical"

	// VectorNetwork represents network-based attacks
	VectorNetwork AttackVector = "network"

	// VectorApplication represents application-layer attacks
	VectorApplication AttackVector = "application"
)

// ThreatLevel represents the threat level of a security assessment
type ThreatLevel string

const (
	// ThreatLevelCritical represents critical threats
	ThreatLevelCritical ThreatLevel = "critical"

	// ThreatLevelHigh represents high-priority threats
	ThreatLevelHigh ThreatLevel = "high"

	// ThreatLevelMedium represents medium-priority threats
	ThreatLevelMedium ThreatLevel = "medium"

	// ThreatLevelLow represents low-priority threats
	ThreatLevelLow ThreatLevel = "low"

	// ThreatLevelInfo represents informational findings
	ThreatLevelInfo ThreatLevel = "info"
)

// DomainCapability represents specific capabilities within security domains
type DomainCapability struct {
	Domain      SecurityDomain    `json:"domain"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Categories  []PayloadCategory `json:"categories"`
	Vectors     []AttackVector    `json:"vectors"`
	Examples    []string          `json:"examples"`
}

// GetAllDomains returns all available security domains
func GetAllDomains() []SecurityDomain {
	return []SecurityDomain{
		DomainModel,
		DomainData,
		DomainInterface,
		DomainInfrastructure,
		DomainOutput,
		DomainProcess,
	}
}

// GetAllPayloadCategories returns all available payload categories
func GetAllPayloadCategories() []PayloadCategory {
	return []PayloadCategory{
		PayloadCategoryPrompt,
		PayloadCategoryQuery,
		PayloadCategoryInput,
		PayloadCategoryCode,
		PayloadCategoryData,
		PayloadCategoryScript,
		PayloadCategoryConfig,
		PayloadCategoryNetwork,
	}
}

// GetAllAttackVectors returns all available attack vectors
func GetAllAttackVectors() []AttackVector {
	return []AttackVector{
		VectorDirect,
		VectorIndirect,
		VectorSocial,
		VectorPhysical,
		VectorNetwork,
		VectorApplication,
	}
}

// GetAllThreatLevels returns all available threat levels
func GetAllThreatLevels() []ThreatLevel {
	return []ThreatLevel{
		ThreatLevelCritical,
		ThreatLevelHigh,
		ThreatLevelMedium,
		ThreatLevelLow,
		ThreatLevelInfo,
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

// IsValidPayloadCategory checks if a payload category is valid
func IsValidPayloadCategory(category PayloadCategory) bool {
	switch category {
	case PayloadCategoryPrompt, PayloadCategoryQuery, PayloadCategoryInput, PayloadCategoryCode,
		PayloadCategoryData, PayloadCategoryScript, PayloadCategoryConfig, PayloadCategoryNetwork:
		return true
	default:
		return false
	}
}

// IsValidAttackVector checks if an attack vector is valid
func IsValidAttackVector(vector AttackVector) bool {
	switch vector {
	case VectorDirect, VectorIndirect, VectorSocial, VectorPhysical, VectorNetwork, VectorApplication:
		return true
	default:
		return false
	}
}

// IsValidThreatLevel checks if a threat level is valid
func IsValidThreatLevel(level ThreatLevel) bool {
	switch level {
	case ThreatLevelCritical, ThreatLevelHigh, ThreatLevelMedium, ThreatLevelLow, ThreatLevelInfo:
		return true
	default:
		return false
	}
}

// GetDomainDescription returns a description for the given security domain
func GetDomainDescription(domain SecurityDomain) string {
	switch domain {
	case DomainModel:
		return "AI/ML model-specific security assessments including model poisoning, adversarial attacks, and model extraction"
	case DomainData:
		return "Data-centric security assessments including data poisoning, privacy attacks, and data leakage"
	case DomainInterface:
		return "Prompt and interface security assessments including prompt injection, jailbreaking, and input validation"
	case DomainInfrastructure:
		return "System and infrastructure security assessments including container security, API security, and network security"
	case DomainOutput:
		return "Output and response security assessments including content filtering, output validation, and harmful content detection"
	case DomainProcess:
		return "Operational and governance security assessments including compliance checks, audit trails, and policy validation"
	default:
		return "Unknown security domain"
	}
}

// GetCategoryDescription returns a description for the given payload category
func GetCategoryDescription(category PayloadCategory) string {
	switch category {
	case PayloadCategoryPrompt:
		return "Prompt-based security payloads for testing AI model responses"
	case PayloadCategoryQuery:
		return "Query-based security payloads for testing database and search systems"
	case PayloadCategoryInput:
		return "General input-based security payloads for testing input validation"
	case PayloadCategoryCode:
		return "Code-based security payloads for testing code execution and injection"
	case PayloadCategoryData:
		return "Data-based security payloads for testing data processing and validation"
	case PayloadCategoryScript:
		return "Script-based security payloads for testing scripting engines and interpreters"
	case PayloadCategoryConfig:
		return "Configuration-based security payloads for testing configuration parsing and validation"
	case PayloadCategoryNetwork:
		return "Network-based security payloads for testing network protocols and services"
	default:
		return "Unknown payload category"
	}
}

// GetCompatibleCategories returns payload categories that are compatible with a security domain
func GetCompatibleCategories(domain SecurityDomain) []PayloadCategory {
	switch domain {
	case DomainModel:
		return []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput, PayloadCategoryData}
	case DomainData:
		return []PayloadCategory{PayloadCategoryData, PayloadCategoryQuery, PayloadCategoryInput}
	case DomainInterface:
		return []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput, PayloadCategoryCode}
	case DomainInfrastructure:
		return []PayloadCategory{PayloadCategoryNetwork, PayloadCategoryConfig, PayloadCategoryScript}
	case DomainOutput:
		return []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput, PayloadCategoryData}
	case DomainProcess:
		return []PayloadCategory{PayloadCategoryConfig, PayloadCategoryScript, PayloadCategoryQuery}
	default:
		return []PayloadCategory{}
	}
}

// GetCompatibleVectors returns attack vectors that are compatible with a security domain
func GetCompatibleVectors(domain SecurityDomain) []AttackVector {
	switch domain {
	case DomainModel:
		return []AttackVector{VectorDirect, VectorIndirect, VectorApplication}
	case DomainData:
		return []AttackVector{VectorDirect, VectorIndirect, VectorApplication}
	case DomainInterface:
		return []AttackVector{VectorDirect, VectorSocial, VectorApplication}
	case DomainInfrastructure:
		return []AttackVector{VectorNetwork, VectorPhysical, VectorApplication}
	case DomainOutput:
		return []AttackVector{VectorDirect, VectorApplication}
	case DomainProcess:
		return []AttackVector{VectorSocial, VectorApplication, VectorPhysical}
	default:
		return []AttackVector{}
	}
}

// ParseDomain parses a string into a SecurityDomain, case-insensitive
func ParseDomain(s string) (SecurityDomain, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	for _, domain := range GetAllDomains() {
		if string(domain) == normalized {
			return domain, nil
		}
	}
	return "", fmt.Errorf("invalid security domain: %s", s)
}

// ParsePayloadCategory parses a string into a PayloadCategory, case-insensitive
func ParsePayloadCategory(s string) (PayloadCategory, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	for _, category := range GetAllPayloadCategories() {
		if string(category) == normalized {
			return category, nil
		}
	}
	return "", fmt.Errorf("invalid payload category: %s", s)
}

// ParseAttackVector parses a string into an AttackVector, case-insensitive
func ParseAttackVector(s string) (AttackVector, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	for _, vector := range GetAllAttackVectors() {
		if string(vector) == normalized {
			return vector, nil
		}
	}
	return "", fmt.Errorf("invalid attack vector: %s", s)
}

// ParseThreatLevel parses a string into a ThreatLevel, case-insensitive
func ParseThreatLevel(s string) (ThreatLevel, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	for _, level := range GetAllThreatLevels() {
		if string(level) == normalized {
			return level, nil
		}
	}
	return "", fmt.Errorf("invalid threat level: %s", s)
}

// GetDomainCapabilities returns predefined capabilities for each security domain
func GetDomainCapabilities() map[SecurityDomain][]DomainCapability {
	capabilities := make(map[SecurityDomain][]DomainCapability)

	// Model Domain Capabilities
	capabilities[DomainModel] = []DomainCapability{
		{
			Domain:      DomainModel,
			Name:        "adversarial-attacks",
			Description: "Test model resilience against adversarial inputs",
			Categories:  []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput},
			Vectors:     []AttackVector{VectorDirect, VectorApplication},
			Examples:    []string{"adversarial prompts", "input perturbations", "model confusion"},
		},
		{
			Domain:      DomainModel,
			Name:        "model-extraction",
			Description: "Test for model extraction vulnerabilities",
			Categories:  []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryQuery},
			Vectors:     []AttackVector{VectorDirect, VectorIndirect},
			Examples:    []string{"query-based extraction", "API endpoint probing", "response analysis"},
		},
	}

	// Interface Domain Capabilities
	capabilities[DomainInterface] = []DomainCapability{
		{
			Domain:      DomainInterface,
			Name:        "prompt-injection",
			Description: "Test for prompt injection vulnerabilities",
			Categories:  []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput},
			Vectors:     []AttackVector{VectorDirect, VectorSocial},
			Examples:    []string{"system prompt override", "instruction injection", "context manipulation"},
		},
		{
			Domain:      DomainInterface,
			Name:        "input-validation",
			Description: "Test input validation and sanitization",
			Categories:  []PayloadCategory{PayloadCategoryInput, PayloadCategoryCode},
			Vectors:     []AttackVector{VectorDirect, VectorApplication},
			Examples:    []string{"XSS payloads", "SQL injection", "command injection"},
		},
	}

	// Infrastructure Domain Capabilities
	capabilities[DomainInfrastructure] = []DomainCapability{
		{
			Domain:      DomainInfrastructure,
			Name:        "api-security",
			Description: "Test API security and authentication",
			Categories:  []PayloadCategory{PayloadCategoryNetwork, PayloadCategoryConfig},
			Vectors:     []AttackVector{VectorNetwork, VectorApplication},
			Examples:    []string{"API enumeration", "authentication bypass", "rate limiting"},
		},
		{
			Domain:      DomainInfrastructure,
			Name:        "container-security",
			Description: "Test container and deployment security",
			Categories:  []PayloadCategory{PayloadCategoryConfig, PayloadCategoryScript},
			Vectors:     []AttackVector{VectorNetwork, VectorPhysical},
			Examples:    []string{"container escape", "privilege escalation", "secret exposure"},
		},
	}

	// Data Domain Capabilities
	capabilities[DomainData] = []DomainCapability{
		{
			Domain:      DomainData,
			Name:        "data-poisoning",
			Description: "Test for data poisoning vulnerabilities",
			Categories:  []PayloadCategory{PayloadCategoryData, PayloadCategoryInput},
			Vectors:     []AttackVector{VectorDirect, VectorIndirect},
			Examples:    []string{"training data manipulation", "backdoor insertion", "label flipping"},
		},
		{
			Domain:      DomainData,
			Name:        "privacy-attacks",
			Description: "Test for privacy and data leakage vulnerabilities",
			Categories:  []PayloadCategory{PayloadCategoryQuery, PayloadCategoryData},
			Vectors:     []AttackVector{VectorDirect, VectorApplication},
			Examples:    []string{"membership inference", "attribute inference", "data reconstruction"},
		},
	}

	// Output Domain Capabilities
	capabilities[DomainOutput] = []DomainCapability{
		{
			Domain:      DomainOutput,
			Name:        "content-filtering",
			Description: "Test content filtering and moderation systems",
			Categories:  []PayloadCategory{PayloadCategoryPrompt, PayloadCategoryInput},
			Vectors:     []AttackVector{VectorDirect, VectorApplication},
			Examples:    []string{"filter evasion", "harmful content generation", "bias detection"},
		},
	}

	// Process Domain Capabilities
	capabilities[DomainProcess] = []DomainCapability{
		{
			Domain:      DomainProcess,
			Name:        "compliance-checks",
			Description: "Test compliance and governance controls",
			Categories:  []PayloadCategory{PayloadCategoryConfig, PayloadCategoryQuery},
			Vectors:     []AttackVector{VectorApplication, VectorSocial},
			Examples:    []string{"policy violations", "audit trail gaps", "access control bypass"},
		},
	}

	return capabilities
}

// GetCapabilitiesForDomain returns all capabilities for a specific domain
func GetCapabilitiesForDomain(domain SecurityDomain) []DomainCapability {
	allCapabilities := GetDomainCapabilities()
	return allCapabilities[domain]
}

// FindCapability finds a specific capability by name across all domains
func FindCapability(name string) (*DomainCapability, bool) {
	allCapabilities := GetDomainCapabilities()
	for _, domainCapabilities := range allCapabilities {
		for _, capability := range domainCapabilities {
			if capability.Name == name {
				return &capability, true
			}
		}
	}
	return nil, false
}
