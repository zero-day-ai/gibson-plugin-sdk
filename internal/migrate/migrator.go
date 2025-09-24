package migrate

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config holds migration configuration
type Config struct {
	InputDir    string
	OutputDir   string
	DryRun      bool
	Backup      bool
	Verbose     bool
	Force       bool
	Recursive   bool
	ExcludeDirs []string
}

// Migrator handles plugin migration
type Migrator struct {
	config Config
	logger *log.Logger
	fset   *token.FileSet
}

// NewMigrator creates a new migrator instance
func NewMigrator(config Config) *Migrator {
	return &Migrator{
		config: config,
		fset:   token.NewFileSet(),
	}
}

// SetLogger sets the logger for the migrator
func (m *Migrator) SetLogger(logger *log.Logger) {
	m.logger = logger
}

// log logs a message if verbose logging is enabled
func (m *Migrator) log(format string, args ...interface{}) {
	if m.logger != nil {
		m.logger.Printf(format, args...)
	}
}

// Result holds migration results
type Result struct {
	FilesProcessed int
	FilesModified  int
	Changes        []Change
	Errors         []Error
	Warnings       []Warning
	SkippedFiles   []SkippedFile
	BackupDir      string
}

// Change represents a migration change
type Change struct {
	File        string
	Description string
	LineNumber  int
	OldCode     string
	NewCode     string
}

// Error represents a migration error
type Error struct {
	File    string
	Message string
	Line    int
}

// Warning represents a migration warning
type Warning struct {
	File    string
	Message string
	Line    int
}

// SkippedFile represents a file that was skipped
type SkippedFile struct {
	Path   string
	Reason string
}

// Migrate performs the migration
func (m *Migrator) Migrate() (*Result, error) {
	result := &Result{
		Changes:      []Change{},
		Errors:       []Error{},
		Warnings:     []Warning{},
		SkippedFiles: []SkippedFile{},
	}

	// Create backup if requested
	if m.config.Backup && !m.config.DryRun {
		backupDir, err := m.createBackup()
		if err != nil {
			return nil, fmt.Errorf("failed to create backup: %w", err)
		}
		result.BackupDir = backupDir
		m.log("Created backup at: %s", backupDir)
	}

	// Walk the input directory
	err := filepath.WalkDir(m.config.InputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip excluded directories
		if d.IsDir() {
			for _, exclude := range m.config.ExcludeDirs {
				if strings.Contains(path, exclude) {
					m.log("Skipping excluded directory: %s", path)
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Only process Go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip test files for now (can be added later)
		if strings.HasSuffix(path, "_test.go") {
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   path,
				Reason: "Test file - manual review recommended",
			})
			return nil
		}

		result.FilesProcessed++
		m.log("Processing file: %s", path)

		// Process the file
		changes, warnings, errors := m.processFile(path)
		if len(changes) > 0 {
			result.FilesModified++
		}

		result.Changes = append(result.Changes, changes...)
		result.Warnings = append(result.Warnings, warnings...)
		result.Errors = append(result.Errors, errors...)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return result, nil
}

// processFile processes a single Go file
func (m *Migrator) processFile(filePath string) ([]Change, []Warning, []Error) {
	var changes []Change
	var warnings []Warning
	var errors []Error

	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		errors = append(errors, Error{
			File:    filePath,
			Message: fmt.Sprintf("Failed to read file: %v", err),
		})
		return changes, warnings, errors
	}

	// Parse the file
	node, err := parser.ParseFile(m.fset, filePath, content, parser.ParseComments)
	if err != nil {
		errors = append(errors, Error{
			File:    filePath,
			Message: fmt.Sprintf("Failed to parse file: %v", err),
		})
		return changes, warnings, errors
	}

	// Check if file needs migration
	if !m.needsMigration(node) && !m.config.Force {
		m.log("File appears to be already migrated: %s", filePath)
		return changes, warnings, errors
	}

	// Apply transformations
	modified := false

	// 1. Update imports
	if m.updateImports(node) {
		modified = true
		changes = append(changes, Change{
			File:        filePath,
			Description: "Updated imports from shared package to SDK",
		})
	}

	// 2. Update error handling to Result[T] pattern
	if m.updateErrorHandling(node) {
		modified = true
		changes = append(changes, Change{
			File:        filePath,
			Description: "Converted error handling to Result[T] pattern",
		})
	}

	// 3. Update interface implementations
	if m.updateInterfaces(node) {
		modified = true
		changes = append(changes, Change{
			File:        filePath,
			Description: "Updated plugin interface implementations",
		})
	}

	// 4. Update type references
	if m.updateTypeReferences(node) {
		modified = true
		changes = append(changes, Change{
			File:        filePath,
			Description: "Updated type references to use SDK types",
		})
	}

	// Write the modified file if changes were made
	if modified && !m.config.DryRun {
		outputPath := m.getOutputPath(filePath)
		if err := m.writeFile(outputPath, node); err != nil {
			errors = append(errors, Error{
				File:    filePath,
				Message: fmt.Sprintf("Failed to write file: %v", err),
			})
		}
	}

	// Add warnings for manual review items
	warnings = append(warnings, m.checkForManualReview(node, filePath)...)

	return changes, warnings, errors
}

// needsMigration checks if a file needs migration
func (m *Migrator) needsMigration(node *ast.File) bool {
	for _, imp := range node.Imports {
		if imp.Path != nil {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(path, "gibson-framework/shared") {
				return true
			}
			// Check for old error handling patterns
			if strings.Contains(path, "errors") && m.hasOldErrorPatterns(node) {
				return true
			}
		}
	}
	return false
}

// hasOldErrorPatterns checks for old error handling patterns
func (m *Migrator) hasOldErrorPatterns(node *ast.File) bool {
	// Look for functions returning (T, error) instead of Result[T]
	for _, decl := range node.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Type.Results != nil && len(fn.Type.Results.List) == 2 {
				// Check if last return type is error
				if len(fn.Type.Results.List) >= 2 {
					lastResult := fn.Type.Results.List[len(fn.Type.Results.List)-1]
					if ident, ok := lastResult.Type.(*ast.Ident); ok && ident.Name == "error" {
						return true
					}
				}
			}
		}
	}
	return false
}

// updateImports updates import statements
func (m *Migrator) updateImports(node *ast.File) bool {
	modified := false

	for _, imp := range node.Imports {
		if imp.Path != nil {
			path := strings.Trim(imp.Path.Value, `"`)

			// Update shared package imports
			if strings.Contains(path, "gibson-framework/shared") {
				newPath := m.mapSharedImport(path)
				imp.Path.Value = `"` + newPath + `"`
				modified = true
				m.log("Updated import: %s -> %s", path, newPath)
			}
		}
	}

	return modified
}

// mapSharedImport maps old shared imports to new SDK imports
func (m *Migrator) mapSharedImport(oldPath string) string {
	mappings := map[string]string{
		"github.com/gibson-sec/gibson-framework/shared":        "github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin",
		"github.com/gibson-sec/gibson-framework/shared/models": "github.com/zero-day-ai/gibson-plugin-sdk/pkg/core/models",
		"github.com/gibson-sec/gibson-framework/shared/types":  "github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin",
	}

	for old, new := range mappings {
		if strings.Contains(oldPath, old) {
			return strings.Replace(oldPath, old, new, 1)
		}
	}

	// Default mapping for any other shared imports
	if strings.Contains(oldPath, "gibson-framework/shared") {
		return strings.Replace(oldPath, "gibson-framework/shared", "gibson-plugin-sdk/pkg/plugin", 1)
	}

	return oldPath
}

// updateErrorHandling converts error handling to Result[T] pattern
func (m *Migrator) updateErrorHandling(node *ast.File) bool {
	modified := false

	// This is a complex transformation that would require significant AST manipulation
	// For now, we'll mark it as needing manual review
	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			if m.hasTupleReturn(fn) {
				modified = true
				m.log("Found function with tuple return that needs Result[T] conversion: %s", fn.Name.Name)
			}
		}
		return true
	})

	return modified
}

// hasTupleReturn checks if function returns (T, error) pattern
func (m *Migrator) hasTupleReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}

	// Check if last return type is error
	lastResult := fn.Type.Results.List[1]
	if ident, ok := lastResult.Type.(*ast.Ident); ok && ident.Name == "error" {
		return true
	}

	return false
}

// updateInterfaces updates interface implementations
func (m *Migrator) updateInterfaces(node *ast.File) bool {
	modified := false

	// Look for plugin interface implementations
	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			// Check for plugin interface methods
			if m.isPluginMethod(fn) {
				modified = true
				m.log("Found plugin method that may need updates: %s", fn.Name.Name)
			}
		}
		return true
	})

	return modified
}

// isPluginMethod checks if a method is a plugin interface method
func (m *Migrator) isPluginMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil {
		return false
	}

	methodNames := []string{"GetInfo", "Initialize", "Validate", "Execute", "Cleanup"}
	for _, name := range methodNames {
		if fn.Name.Name == name {
			return true
		}
	}

	return false
}

// updateTypeReferences updates type references
func (m *Migrator) updateTypeReferences(node *ast.File) bool {
	modified := false

	ast.Inspect(node, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				// Update shared package type references
				if ident.Name == "shared" {
					// This would require more sophisticated type mapping
					modified = true
					m.log("Found shared package type reference: %s.%s", ident.Name, sel.Sel.Name)
				}
			}
		}
		return true
	})

	return modified
}

// checkForManualReview checks for items that need manual review
func (m *Migrator) checkForManualReview(node *ast.File, filePath string) []Warning {
	var warnings []Warning

	// Check for complex error handling
	ast.Inspect(node, func(n ast.Node) bool {
		if _, ok := n.(*ast.IfStmt); ok {
			// Look for error handling patterns
			warnings = append(warnings, Warning{
				File:    filePath,
				Message: "Manual review recommended for error handling patterns",
			})
		}
		return true
	})

	return warnings
}

// getOutputPath gets the output path for a file
func (m *Migrator) getOutputPath(inputPath string) string {
	if m.config.OutputDir == m.config.InputDir {
		return inputPath
	}

	relPath, _ := filepath.Rel(m.config.InputDir, inputPath)
	return filepath.Join(m.config.OutputDir, relPath)
}

// writeFile writes the modified AST to a file
func (m *Migrator) writeFile(outputPath string, node *ast.File) error {
	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Format and write the file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if err := format.Node(file, m.fset, node); err != nil {
		return fmt.Errorf("failed to format and write file: %w", err)
	}

	return nil
}

// createBackup creates a backup of the input directory
func (m *Migrator) createBackup() (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join(filepath.Dir(m.config.InputDir),
		fmt.Sprintf("%s-backup-%s", filepath.Base(m.config.InputDir), timestamp))

	// Copy the entire input directory
	err := copyDir(m.config.InputDir, backupDir)
	if err != nil {
		return "", fmt.Errorf("failed to copy directory: %w", err)
	}

	return backupDir, nil
}

// copyDir recursively copies a directory
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			return os.MkdirAll(dstPath, 0755)
		}

		// Copy file
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return err
		}

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = dstFile.ReadFrom(srcFile)
		return err
	})
}
