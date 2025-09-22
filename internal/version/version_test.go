package version

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Version
		shouldError bool
	}{
		{
			name:  "basic version",
			input: "1.2.3",
			expected: Version{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			shouldError: false,
		},
		{
			name:  "version with v prefix",
			input: "v2.0.1",
			expected: Version{
				Major: 2,
				Minor: 0,
				Patch: 1,
			},
			shouldError: false,
		},
		{
			name:  "version with pre-release",
			input: "1.0.0-alpha.1",
			expected: Version{
				Major:      1,
				Minor:      0,
				Patch:      0,
				PreRelease: "alpha.1",
			},
			shouldError: false,
		},
		{
			name:  "version with build metadata",
			input: "1.0.0+20230101.abcdef",
			expected: Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
				Build: "20230101.abcdef",
			},
			shouldError: false,
		},
		{
			name:  "full version",
			input: "2.1.0-beta.2+build.123",
			expected: Version{
				Major:      2,
				Minor:      1,
				Patch:      0,
				PreRelease: "beta.2",
				Build:      "build.123",
			},
			shouldError: false,
		},
		{
			name:        "invalid format",
			input:       "1.2",
			shouldError: true,
		},
		{
			name:        "empty string",
			input:       "",
			shouldError: true,
		},
		{
			name:        "invalid characters",
			input:       "1.2.3.4",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Parse(tt.input)
			if tt.shouldError {
				if result.IsOk() {
					t.Errorf("expected error but got none")
				}
				return
			}

			if result.IsErr() {
				t.Errorf("unexpected error: %v", result.Error())
				return
			}

			version := result.Unwrap()
			if version.Major != tt.expected.Major ||
				version.Minor != tt.expected.Minor ||
				version.Patch != tt.expected.Patch ||
				version.PreRelease != tt.expected.PreRelease ||
				version.Build != tt.expected.Build {
				t.Errorf("expected %+v, got %+v", tt.expected, version)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		name     string
		version  Version
		expected string
	}{
		{
			name: "basic version",
			version: Version{
				Major: 1,
				Minor: 2,
				Patch: 3,
			},
			expected: "1.2.3",
		},
		{
			name: "version with pre-release",
			version: Version{
				Major:      1,
				Minor:      0,
				Patch:      0,
				PreRelease: "alpha.1",
			},
			expected: "1.0.0-alpha.1",
		},
		{
			name: "version with build",
			version: Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
				Build: "build.123",
			},
			expected: "1.0.0+build.123",
		},
		{
			name: "full version",
			version: Version{
				Major:      2,
				Minor:      1,
				Patch:      0,
				PreRelease: "beta.2",
				Build:      "build.123",
			},
			expected: "2.1.0-beta.2+build.123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.version.String(); got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "equal versions",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "major version difference",
			v1:       "2.0.0",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "minor version difference",
			v1:       "1.1.0",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "patch version difference",
			v1:       "1.0.1",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "v1 less than v2",
			v1:       "1.0.0",
			v2:       "2.0.0",
			expected: -1,
		},
		{
			name:     "pre-release vs release",
			v1:       "1.0.0-alpha",
			v2:       "1.0.0",
			expected: -1,
		},
		{
			name:     "pre-release comparison",
			v1:       "1.0.0-beta",
			v2:       "1.0.0-alpha",
			expected: 1,
		},
		{
			name:     "numeric pre-release",
			v1:       "1.0.0-alpha.2",
			v2:       "1.0.0-alpha.1",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1Result := Parse(tt.v1)
			v2Result := Parse(tt.v2)

			if v1Result.IsErr() || v2Result.IsErr() {
				t.Fatalf("failed to parse versions: v1=%v, v2=%v", v1Result.Error(), v2Result.Error())
			}

			v1 := v1Result.Unwrap()
			v2 := v2Result.Unwrap()

			if got := v1.Compare(v2); got != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, got)
			}
		})
	}
}

func TestVersionRangeContains(t *testing.T) {
	tests := []struct {
		name     string
		vrange   VersionRange
		version  string
		expected bool
	}{
		{
			name: "version in range inclusive",
			vrange: VersionRange{
				Min:        Version{Major: 1, Minor: 0, Patch: 0},
				Max:        Version{Major: 2, Minor: 0, Patch: 0},
				IncludeMin: true,
				IncludeMax: true,
			},
			version:  "1.5.0",
			expected: true,
		},
		{
			name: "version at min boundary inclusive",
			vrange: VersionRange{
				Min:        Version{Major: 1, Minor: 0, Patch: 0},
				Max:        Version{Major: 2, Minor: 0, Patch: 0},
				IncludeMin: true,
				IncludeMax: false,
			},
			version:  "1.0.0",
			expected: true,
		},
		{
			name: "version at max boundary exclusive",
			vrange: VersionRange{
				Min:        Version{Major: 1, Minor: 0, Patch: 0},
				Max:        Version{Major: 2, Minor: 0, Patch: 0},
				IncludeMin: true,
				IncludeMax: false,
			},
			version:  "2.0.0",
			expected: false,
		},
		{
			name: "version below range",
			vrange: VersionRange{
				Min:        Version{Major: 1, Minor: 0, Patch: 0},
				Max:        Version{Major: 2, Minor: 0, Patch: 0},
				IncludeMin: true,
				IncludeMax: true,
			},
			version:  "0.9.0",
			expected: false,
		},
		{
			name: "version above range",
			vrange: VersionRange{
				Min:        Version{Major: 1, Minor: 0, Patch: 0},
				Max:        Version{Major: 2, Minor: 0, Patch: 0},
				IncludeMin: true,
				IncludeMax: true,
			},
			version:  "2.1.0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versionResult := Parse(tt.version)
			if versionResult.IsErr() {
				t.Fatalf("failed to parse version: %v", versionResult.Error())
			}

			version := versionResult.Unwrap()
			if got := tt.vrange.Contains(version); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestCompatibilityChecker(t *testing.T) {
	checker := NewCompatibilityChecker()

	tests := []struct {
		name             string
		sdkVersion       string
		frameworkVersion string
		expectedLevel    CompatibilityLevel
		shouldError      bool
	}{
		{
			name:             "compatible versions",
			sdkVersion:       "1.0.0",
			frameworkVersion: "2.0.0",
			expectedLevel:    Compatible,
			shouldError:      false,
		},
		{
			name:             "deprecated framework version",
			sdkVersion:       "1.0.0",
			frameworkVersion: "1.2.0",
			expectedLevel:    Incompatible,
			shouldError:      false,
		},
		{
			name:             "major version mismatch",
			sdkVersion:       "1.0.0",
			frameworkVersion: "3.0.0",
			expectedLevel:    MajorIncompatible,
			shouldError:      false,
		},
		{
			name:             "invalid SDK version",
			sdkVersion:       "invalid",
			frameworkVersion: "2.0.0",
			shouldError:      true,
		},
		{
			name:             "invalid framework version",
			sdkVersion:       "1.0.0",
			frameworkVersion: "invalid",
			shouldError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.CheckCompatibility(tt.sdkVersion, tt.frameworkVersion)

			if tt.shouldError {
				if result.IsOk() {
					t.Errorf("expected error but got none")
				}
				return
			}

			if result.IsErr() {
				t.Errorf("unexpected error: %v", result.Error())
				return
			}

			compatResult := result.Unwrap()
			if compatResult.Level != tt.expectedLevel {
				t.Errorf("expected level %v, got %v", tt.expectedLevel, compatResult.Level)
			}
		})
	}
}

func TestCompatibilityResult(t *testing.T) {
	t.Run("IsCompatible", func(t *testing.T) {
		result := CompatibilityResult{Level: Compatible}
		if !result.IsCompatible() {
			t.Errorf("expected compatible result to return true")
		}

		result.Level = Incompatible
		if result.IsCompatible() {
			t.Errorf("expected incompatible result to return false")
		}
	})

	t.Run("IsDeprecated", func(t *testing.T) {
		result := CompatibilityResult{Warnings: []string{"deprecated"}}
		if !result.IsDeprecated() {
			t.Errorf("expected result with warnings to be deprecated")
		}

		result.Warnings = []string{}
		if result.IsDeprecated() {
			t.Errorf("expected result without warnings to not be deprecated")
		}
	})

	t.Run("GetRecommendation", func(t *testing.T) {
		tests := []struct {
			level         CompatibilityLevel
			migration     string
			shouldContain string
		}{
			{Compatible, "", "fully compatible"},
			{Compatible, "upgrade", "consider upgrading"},
			{MinorIncompatible, "", "Minor incompatibility"},
			{MajorIncompatible, "", "Major incompatibility"},
			{Incompatible, "", "incompatible"},
		}

		for _, tt := range tests {
			result := CompatibilityResult{
				Level:         tt.level,
				MigrationPath: tt.migration,
			}
			recommendation := result.GetRecommendation()
			if recommendation == "" {
				t.Errorf("expected non-empty recommendation for level %v", tt.level)
			}
		}
	})
}

func TestCompareVersionStrings(t *testing.T) {
	tests := []struct {
		name        string
		v1          string
		v2          string
		expected    int
		shouldError bool
	}{
		{
			name:     "equal versions",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "v1 greater",
			v1:       "2.0.0",
			v2:       "1.0.0",
			expected: 1,
		},
		{
			name:     "v1 less",
			v1:       "1.0.0",
			v2:       "2.0.0",
			expected: -1,
		},
		{
			name:        "invalid v1",
			v1:          "invalid",
			v2:          "1.0.0",
			shouldError: true,
		},
		{
			name:        "invalid v2",
			v1:          "1.0.0",
			v2:          "invalid",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersionStrings(tt.v1, tt.v2)

			if tt.shouldError {
				if result.IsOk() {
					t.Errorf("expected error but got none")
				}
				return
			}

			if result.IsErr() {
				t.Errorf("unexpected error: %v", result.Error())
				return
			}

			if got := result.Unwrap(); got != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, got)
			}
		})
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		shouldError bool
	}{
		{
			name:        "valid version",
			version:     "1.0.0",
			shouldError: false,
		},
		{
			name:        "valid version with prefix",
			version:     "v2.1.3",
			shouldError: false,
		},
		{
			name:        "invalid version",
			version:     "1.2",
			shouldError: true,
		},
		{
			name:        "empty version",
			version:     "",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateVersion(tt.version)

			if tt.shouldError {
				if result.IsOk() {
					t.Errorf("expected error but got none")
				}
			} else {
				if result.IsErr() {
					t.Errorf("unexpected error: %v", result.Error())
				}
			}
		})
	}
}
