package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/zero-day-ai/gibson-sdk/pkg/core/models"
)

// Version represents a semantic version
type Version struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease string
	Build      string
}

// String returns the string representation of the version
func (v Version) String() string {
	version := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.PreRelease != "" {
		version += "-" + v.PreRelease
	}
	if v.Build != "" {
		version += "+" + v.Build
	}
	return version
}

// CompatibilityLevel represents the level of compatibility between versions
type CompatibilityLevel int

const (
	Compatible CompatibilityLevel = iota
	MinorIncompatible
	MajorIncompatible
	Incompatible
)

func (cl CompatibilityLevel) String() string {
	switch cl {
	case Compatible:
		return "compatible"
	case MinorIncompatible:
		return "minor_incompatible"
	case MajorIncompatible:
		return "major_incompatible"
	case Incompatible:
		return "incompatible"
	default:
		return "unknown"
	}
}

// CompatibilityMatrix defines version compatibility rules
type CompatibilityMatrix struct {
	SDKVersion       Version
	FrameworkRanges  []VersionRange
	DeprecatedRanges []VersionRange
}

// VersionRange represents a range of compatible versions
type VersionRange struct {
	Min           Version
	Max           Version
	IncludeMin    bool
	IncludeMax    bool
	Description   string
	MigrationPath string
}

// Contains checks if a version is within the range
func (vr VersionRange) Contains(v Version) bool {
	minCheck := v.Compare(vr.Min)
	maxCheck := v.Compare(vr.Max)

	minSatisfied := minCheck > 0 || (minCheck == 0 && vr.IncludeMin)
	maxSatisfied := maxCheck < 0 || (maxCheck == 0 && vr.IncludeMax)

	return minSatisfied && maxSatisfied
}

// String returns a string representation of the version range
func (vr VersionRange) String() string {
	minBracket := "("
	maxBracket := ")"
	if vr.IncludeMin {
		minBracket = "["
	}
	if vr.IncludeMax {
		maxBracket = "]"
	}
	return fmt.Sprintf("%s%s, %s%s", minBracket, vr.Min.String(), vr.Max.String(), maxBracket)
}

// Parser for semantic version strings
var semverRegex = regexp.MustCompile(`^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// Parse parses a semantic version string
func Parse(versionStr string) models.Result[Version] {
	versionStr = strings.TrimSpace(versionStr)
	if versionStr == "" {
		return models.Err[Version](fmt.Errorf("version string cannot be empty"))
	}

	// Remove 'v' prefix if present
	if strings.HasPrefix(versionStr, "v") {
		versionStr = versionStr[1:]
	}

	matches := semverRegex.FindStringSubmatch(versionStr)
	if matches == nil {
		return models.Err[Version](fmt.Errorf("invalid semantic version format: %s", versionStr))
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return models.Err[Version](fmt.Errorf("invalid major version: %s", matches[1]))
	}

	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return models.Err[Version](fmt.Errorf("invalid minor version: %s", matches[2]))
	}

	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		return models.Err[Version](fmt.Errorf("invalid patch version: %s", matches[3]))
	}

	version := Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		PreRelease: matches[4],
		Build:      matches[5],
	}

	return models.Ok(version)
}

// Compare compares two versions
// Returns: -1 if v < other, 0 if v == other, 1 if v > other
func (v Version) Compare(other Version) int {
	// Compare major version
	if v.Major != other.Major {
		if v.Major > other.Major {
			return 1
		}
		return -1
	}

	// Compare minor version
	if v.Minor != other.Minor {
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	}

	// Compare patch version
	if v.Patch != other.Patch {
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}

	// Compare pre-release versions
	return comparePreRelease(v.PreRelease, other.PreRelease)
}

// comparePreRelease compares pre-release versions according to semver rules
func comparePreRelease(v1, v2 string) int {
	// No pre-release is higher than any pre-release
	if v1 == "" && v2 == "" {
		return 0
	}
	if v1 == "" {
		return 1
	}
	if v2 == "" {
		return -1
	}

	// Split pre-release identifiers
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		p1, p2 := parts1[i], parts2[i]

		// Try to parse as integers
		n1, err1 := strconv.Atoi(p1)
		n2, err2 := strconv.Atoi(p2)

		if err1 == nil && err2 == nil {
			// Both are numbers
			if n1 != n2 {
				if n1 > n2 {
					return 1
				}
				return -1
			}
		} else if err1 == nil {
			// p1 is number, p2 is string - numbers have lower precedence
			return -1
		} else if err2 == nil {
			// p1 is string, p2 is number - strings have higher precedence
			return 1
		} else {
			// Both are strings
			if p1 != p2 {
				if p1 > p2 {
					return 1
				}
				return -1
			}
		}
	}

	// If one has more parts, it's considered higher
	if len(parts1) != len(parts2) {
		if len(parts1) > len(parts2) {
			return 1
		}
		return -1
	}

	return 0
}

// SDKVersion is the current SDK version
var SDKVersion = Version{
	Major: 1,
	Minor: 0,
	Patch: 0,
}

// CompatibilityChecker manages version compatibility checking
type CompatibilityChecker struct {
	matrices map[string]CompatibilityMatrix
}

// NewCompatibilityChecker creates a new compatibility checker with default matrices
func NewCompatibilityChecker() *CompatibilityChecker {
	checker := &CompatibilityChecker{
		matrices: make(map[string]CompatibilityMatrix),
	}
	checker.loadDefaultMatrices()
	return checker
}

// loadDefaultMatrices loads the default compatibility matrices
func (c *CompatibilityChecker) loadDefaultMatrices() {
	// SDK v1.0.x compatibility matrix
	c.matrices["1.0.x"] = CompatibilityMatrix{
		SDKVersion: Version{Major: 1, Minor: 0, Patch: 0},
		FrameworkRanges: []VersionRange{
			{
				Min:           Version{Major: 2, Minor: 0, Patch: 0},
				Max:           Version{Major: 2, Minor: 99, Patch: 99},
				IncludeMin:    true,
				IncludeMax:    true,
				Description:   "Full compatibility with Gibson Framework v2.x",
				MigrationPath: "",
			},
			{
				Min:           Version{Major: 1, Minor: 5, Patch: 0},
				Max:           Version{Major: 1, Minor: 99, Patch: 99},
				IncludeMin:    true,
				IncludeMax:    true,
				Description:   "Limited compatibility with Gibson Framework v1.5+",
				MigrationPath: "upgrade_to_v2",
			},
		},
		DeprecatedRanges: []VersionRange{
			{
				Min:           Version{Major: 1, Minor: 0, Patch: 0},
				Max:           Version{Major: 1, Minor: 4, Patch: 99},
				IncludeMin:    true,
				IncludeMax:    true,
				Description:   "Deprecated framework versions - security vulnerabilities",
				MigrationPath: "urgent_upgrade_required",
			},
		},
	}

	// Future SDK versions can be added here
	c.matrices["1.1.x"] = CompatibilityMatrix{
		SDKVersion: Version{Major: 1, Minor: 1, Patch: 0},
		FrameworkRanges: []VersionRange{
			{
				Min:           Version{Major: 2, Minor: 1, Patch: 0},
				Max:           Version{Major: 2, Minor: 99, Patch: 99},
				IncludeMin:    true,
				IncludeMax:    true,
				Description:   "Full compatibility with Gibson Framework v2.1+",
				MigrationPath: "",
			},
		},
	}
}

// CheckCompatibility checks if SDK and framework versions are compatible
func (c *CompatibilityChecker) CheckCompatibility(sdkVersion, frameworkVersion string) models.Result[CompatibilityResult] {
	sdkVer := Parse(sdkVersion)
	if sdkVer.IsErr() {
		return models.Err[CompatibilityResult](fmt.Errorf("invalid SDK version: %w", sdkVer.Error()))
	}

	frameworkVer := Parse(frameworkVersion)
	if frameworkVer.IsErr() {
		return models.Err[CompatibilityResult](fmt.Errorf("invalid framework version: %w", frameworkVer.Error()))
	}

	return c.CheckCompatibilityVersions(sdkVer.Unwrap(), frameworkVer.Unwrap())
}

// CheckCompatibilityVersions checks compatibility between parsed versions
func (c *CompatibilityChecker) CheckCompatibilityVersions(sdkVer, frameworkVer Version) models.Result[CompatibilityResult] {
	// Find the appropriate compatibility matrix
	matrixKey := fmt.Sprintf("%d.%d.x", sdkVer.Major, sdkVer.Minor)
	matrix, exists := c.matrices[matrixKey]
	if !exists {
		// Fall back to major version compatibility
		matrixKey = fmt.Sprintf("%d.0.x", sdkVer.Major)
		matrix, exists = c.matrices[matrixKey]
		if !exists {
			return models.Err[CompatibilityResult](fmt.Errorf("no compatibility matrix found for SDK version %s", sdkVer.String()))
		}
	}

	result := CompatibilityResult{
		SDKVersion:       sdkVer,
		FrameworkVersion: frameworkVer,
		Level:            Incompatible,
		Message:          "Versions are incompatible",
		Warnings:         []string{},
		MigrationPath:    "",
	}

	// Check deprecated ranges first
	for _, depRange := range matrix.DeprecatedRanges {
		if depRange.Contains(frameworkVer) {
			result.Level = Incompatible
			result.Message = fmt.Sprintf("Framework version %s is deprecated: %s", frameworkVer.String(), depRange.Description)
			result.MigrationPath = depRange.MigrationPath
			result.Warnings = append(result.Warnings, "Using deprecated framework version with known security issues")
			return models.Ok(result)
		}
	}

	// Check compatible ranges
	for _, compatRange := range matrix.FrameworkRanges {
		if compatRange.Contains(frameworkVer) {
			result.Level = Compatible
			result.Message = fmt.Sprintf("SDK v%s is compatible with Framework v%s", sdkVer.String(), frameworkVer.String())
			result.Description = compatRange.Description
			result.MigrationPath = compatRange.MigrationPath

			// Add warnings for edge cases
			if compatRange.MigrationPath != "" {
				result.Warnings = append(result.Warnings, "Consider upgrading for better compatibility")
			}

			return models.Ok(result)
		}
	}

	// Check for major/minor incompatibilities
	if sdkVer.Major != frameworkVer.Major {
		result.Level = MajorIncompatible
		result.Message = fmt.Sprintf("Major version mismatch: SDK v%s vs Framework v%s", sdkVer.String(), frameworkVer.String())
		result.MigrationPath = "major_version_upgrade"
	} else if abs(sdkVer.Minor-frameworkVer.Minor) > 2 {
		result.Level = MinorIncompatible
		result.Message = fmt.Sprintf("Minor version difference too large: SDK v%s vs Framework v%s", sdkVer.String(), frameworkVer.String())
		result.MigrationPath = "minor_version_upgrade"
	}

	return models.Ok(result)
}

// CompatibilityResult contains the result of a compatibility check
type CompatibilityResult struct {
	SDKVersion       Version            `json:"sdk_version"`
	FrameworkVersion Version            `json:"framework_version"`
	Level            CompatibilityLevel `json:"level"`
	Message          string             `json:"message"`
	Description      string             `json:"description,omitempty"`
	Warnings         []string           `json:"warnings,omitempty"`
	MigrationPath    string             `json:"migration_path,omitempty"`
}

// IsCompatible returns true if the versions are compatible
func (cr CompatibilityResult) IsCompatible() bool {
	return cr.Level == Compatible
}

// IsDeprecated returns true if either version is deprecated
func (cr CompatibilityResult) IsDeprecated() bool {
	return len(cr.Warnings) > 0
}

// GetRecommendation returns a human-readable recommendation
func (cr CompatibilityResult) GetRecommendation() string {
	switch cr.Level {
	case Compatible:
		if cr.MigrationPath != "" {
			return fmt.Sprintf("Compatible but consider upgrading: %s", cr.Description)
		}
		return "Versions are fully compatible"
	case MinorIncompatible:
		return "Minor incompatibility detected. Update to a compatible version."
	case MajorIncompatible:
		return "Major incompatibility detected. Significant changes required."
	case Incompatible:
		return "Versions are incompatible. Please check compatibility matrix."
	default:
		return "Unknown compatibility status"
	}
}

// Utility functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// GetCurrentSDKVersion returns the current SDK version
func GetCurrentSDKVersion() Version {
	return SDKVersion
}

// ValidateVersion validates that a version string is properly formatted
func ValidateVersion(versionStr string) models.Result[bool] {
	result := Parse(versionStr)
	if result.IsErr() {
		return models.Err[bool](result.Error())
	}
	return models.Ok(true)
}

// CompareVersionStrings compares two version strings
func CompareVersionStrings(v1, v2 string) models.Result[int] {
	ver1 := Parse(v1)
	if ver1.IsErr() {
		return models.Err[int](fmt.Errorf("invalid version v1: %w", ver1.Error()))
	}

	ver2 := Parse(v2)
	if ver2.IsErr() {
		return models.Err[int](fmt.Errorf("invalid version v2: %w", ver2.Error()))
	}

	return models.Ok(ver1.Unwrap().Compare(ver2.Unwrap()))
}
