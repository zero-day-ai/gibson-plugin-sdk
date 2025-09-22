package migrate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrator_needsMigration(t *testing.T) {
	migrator := NewMigrator(Config{})

	tests := []struct {
		name     string
		code     string
		expected bool
	}{
		{
			name: "needs migration - shared import",
			code: `package main

import "github.com/gibson-sec/gibson-framework/shared"

func main() {}`,
			expected: true,
		},
		{
			name: "needs migration - shared models import",
			code: `package main

import "github.com/gibson-sec/gibson-framework/shared/models"

func main() {}`,
			expected: true,
		},
		{
			name: "already migrated - SDK import",
			code: `package main

import "github.com/zero-day-ai/gibson-sdk/pkg/plugin"

func main() {}`,
			expected: false,
		},
		{
			name: "no migration needed - standard library",
			code: `package main

import "fmt"

func main() {
	fmt.Println("hello")
}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseTestCode(t, tt.code)
			result := migrator.needsMigration(node)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMigrator_updateImports(t *testing.T) {
	migrator := NewMigrator(Config{})

	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name: "update shared import",
			code: `package main

import "github.com/gibson-sec/gibson-framework/shared"`,
			expected: `"github.com/zero-day-ai/gibson-sdk/pkg/plugin"`,
		},
		{
			name: "update shared models import",
			code: `package main

import "github.com/gibson-sec/gibson-framework/shared/models"`,
			expected: `"github.com/zero-day-ai/gibson-sdk/pkg/core/models"`,
		},
		{
			name: "no change for other imports",
			code: `package main

import "fmt"`,
			expected: `"fmt"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseTestCode(t, tt.code)
			migrator.updateImports(node)

			if len(node.Imports) > 0 {
				importPath := node.Imports[0].Path.Value
				if importPath != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, importPath)
				}
			}
		})
	}
}

func TestMigrator_mapSharedImport(t *testing.T) {
	migrator := NewMigrator(Config{})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic shared import",
			input:    "github.com/gibson-sec/gibson-framework/shared",
			expected: "github.com/zero-day-ai/gibson-sdk/pkg/plugin",
		},
		{
			name:     "shared models import",
			input:    "github.com/gibson-sec/gibson-framework/shared/models",
			expected: "github.com/zero-day-ai/gibson-sdk/pkg/core/models",
		},
		{
			name:     "shared types import",
			input:    "github.com/gibson-sec/gibson-framework/shared/types",
			expected: "github.com/zero-day-ai/gibson-sdk/pkg/plugin",
		},
		{
			name:     "non-shared import unchanged",
			input:    "github.com/gibson-sec/gibson-framework/pkg/core",
			expected: "github.com/gibson-sec/gibson-framework/pkg/core",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := migrator.mapSharedImport(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestMigrator_hasTupleReturn(t *testing.T) {
	migrator := NewMigrator(Config{})

	tests := []struct {
		name     string
		code     string
		expected bool
	}{
		{
			name: "function with tuple return",
			code: `package main

func getData() (string, error) {
	return "", nil
}`,
			expected: true,
		},
		{
			name: "function with single return",
			code: `package main

func getData() string {
	return ""
}`,
			expected: false,
		},
		{
			name: "function with no return",
			code: `package main

func doSomething() {
}`,
			expected: false,
		},
		{
			name: "function with three returns",
			code: `package main

func getData() (string, int, error) {
	return "", 0, nil
}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseTestCode(t, tt.code)
			var fn *ast.FuncDecl
			for _, decl := range node.Decls {
				if f, ok := decl.(*ast.FuncDecl); ok {
					fn = f
					break
				}
			}

			if fn == nil {
				t.Fatal("no function found in test code")
			}

			result := migrator.hasTupleReturn(fn)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMigrator_isPluginMethod(t *testing.T) {
	migrator := NewMigrator(Config{})

	tests := []struct {
		name     string
		code     string
		expected bool
	}{
		{
			name: "Execute method",
			code: `package main

type Plugin struct{}

func (p *Plugin) Execute() {
}`,
			expected: true,
		},
		{
			name: "GetInfo method",
			code: `package main

type Plugin struct{}

func (p *Plugin) GetInfo() {
}`,
			expected: true,
		},
		{
			name: "regular method",
			code: `package main

type Plugin struct{}

func (p *Plugin) SomeMethod() {
}`,
			expected: false,
		},
		{
			name: "function not method",
			code: `package main

func Execute() {
}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := parseTestCode(t, tt.code)
			var fn *ast.FuncDecl
			for _, decl := range node.Decls {
				if f, ok := decl.(*ast.FuncDecl); ok {
					fn = f
					break
				}
			}

			if fn == nil {
				t.Fatal("no function found in test code")
			}

			result := migrator.isPluginMethod(fn)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestMigrator_processFile(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "migrate-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create test file
	testFile := filepath.Join(tempDir, "test.go")
	testCode := `package main

import "github.com/gibson-sec/gibson-framework/shared"

type Plugin struct{}

func (p *Plugin) Execute() (string, error) {
	return "", nil
}

func main() {}
`

	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatal(err)
	}

	migrator := NewMigrator(Config{
		InputDir:  tempDir,
		OutputDir: tempDir,
		DryRun:    true,
	})

	changes, warnings, errors := migrator.processFile(testFile)

	// Should have changes for import updates
	if len(changes) == 0 {
		t.Error("expected changes but got none")
	}

	// Should have no errors
	if len(errors) > 0 {
		t.Errorf("unexpected errors: %v", errors)
	}

	// Check that changes include import updates
	foundImportChange := false
	for _, change := range changes {
		if strings.Contains(change.Description, "import") {
			foundImportChange = true
			break
		}
	}

	if !foundImportChange {
		t.Error("expected import change but didn't find one")
	}
}

func TestMigrator_createBackup(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "migrate-backup-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create source directory with test files
	srcDir := filepath.Join(tempDir, "source")
	err = os.MkdirAll(srcDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(srcDir, "test.go")
	err = os.WriteFile(testFile, []byte("package main\n\nfunc main() {}"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	migrator := NewMigrator(Config{
		InputDir: srcDir,
	})

	backupDir, err := migrator.createBackup()
	if err != nil {
		t.Fatal(err)
	}

	// Check that backup was created
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		t.Error("backup directory was not created")
	}

	// Check that backup contains the test file
	backupFile := filepath.Join(backupDir, "test.go")
	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		t.Error("backup file was not created")
	}

	// Verify backup content
	content, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatal(err)
	}

	expectedContent := "package main\n\nfunc main() {}"
	if string(content) != expectedContent {
		t.Errorf("backup content mismatch. expected %q, got %q", expectedContent, string(content))
	}
}

func TestMigrator_getOutputPath(t *testing.T) {
	tests := []struct {
		name      string
		inputDir  string
		outputDir string
		inputPath string
		expected  string
	}{
		{
			name:      "same input and output dir",
			inputDir:  "/src",
			outputDir: "/src",
			inputPath: "/src/plugin.go",
			expected:  "/src/plugin.go",
		},
		{
			name:      "different output dir",
			inputDir:  "/src",
			outputDir: "/dst",
			inputPath: "/src/plugin.go",
			expected:  "/dst/plugin.go",
		},
		{
			name:      "nested file different output dir",
			inputDir:  "/src",
			outputDir: "/dst",
			inputPath: "/src/subdir/plugin.go",
			expected:  "/dst/subdir/plugin.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migrator := NewMigrator(Config{
				InputDir:  tt.inputDir,
				OutputDir: tt.outputDir,
			})

			result := migrator.getOutputPath(tt.inputPath)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Helper function to parse test code into AST
func parseTestCode(t *testing.T, code string) *ast.File {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "test.go", code, parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse test code: %v", err)
	}
	return node
}
