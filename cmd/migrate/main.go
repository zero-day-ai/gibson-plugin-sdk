package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/zero-day-ai/gibson-sdk/internal/migrate"
)

const (
	version = "1.0.0"
	banner  = `
Gibson Plugin SDK Migration Tool v%s
=====================================

This tool helps migrate existing Gibson plugins to use the new SDK.
It performs the following transformations:

1. Updates import statements from shared package to SDK
2. Converts error handling to Result[T] pattern
3. Updates interface implementations
4. Modernizes plugin structure

Use --help for detailed usage information.
`
)

func main() {
	var (
		pluginDir   = flag.String("plugin-dir", ".", "Directory containing plugin code to migrate")
		outputDir   = flag.String("output-dir", "", "Output directory for migrated code (default: overwrites input)")
		dryRun      = flag.Bool("dry-run", false, "Show what would be changed without applying changes")
		backup      = flag.Bool("backup", true, "Create backup of original files before migration")
		verbose     = flag.Bool("verbose", false, "Enable verbose logging")
		force       = flag.Bool("force", false, "Force migration even if target appears to be already migrated")
		recursive   = flag.Bool("recursive", true, "Recursively process subdirectories")
		exclude     = flag.String("exclude", "vendor,node_modules,.git", "Comma-separated list of directories to exclude")
		showVersion = flag.Bool("version", false, "Show version information")
		showHelp    = flag.Bool("help", false, "Show help information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("Gibson Plugin SDK Migration Tool v%s\n", version)
		os.Exit(0)
	}

	if *showHelp {
		fmt.Printf(banner, version)
		flag.Usage()
		fmt.Println("\nExamples:")
		fmt.Println("  # Dry run to see what would be changed")
		fmt.Println("  gibson-migrate --plugin-dir ./my-plugin --dry-run")
		fmt.Println("")
		fmt.Println("  # Migrate plugin with backup")
		fmt.Println("  gibson-migrate --plugin-dir ./my-plugin --backup")
		fmt.Println("")
		fmt.Println("  # Migrate to different output directory")
		fmt.Println("  gibson-migrate --plugin-dir ./old-plugin --output-dir ./migrated-plugin")
		fmt.Println("")
		fmt.Println("  # Migrate all plugins in directory")
		fmt.Println("  gibson-migrate --plugin-dir ./plugins --recursive")
		os.Exit(0)
	}

	// Validate input directory
	if _, err := os.Stat(*pluginDir); os.IsNotExist(err) {
		log.Fatalf("Plugin directory does not exist: %s", *pluginDir)
	}

	// Set default output directory
	if *outputDir == "" {
		*outputDir = *pluginDir
	}

	// Configure migrator
	config := migrate.Config{
		InputDir:    *pluginDir,
		OutputDir:   *outputDir,
		DryRun:      *dryRun,
		Backup:      *backup,
		Verbose:     *verbose,
		Force:       *force,
		Recursive:   *recursive,
		ExcludeDirs: parseExcludeDirs(*exclude),
	}

	// Create migrator
	migrator := migrate.NewMigrator(config)

	// Setup logging
	if *verbose {
		migrator.SetLogger(log.New(os.Stdout, "[MIGRATE] ", log.LstdFlags))
	}

	fmt.Printf(banner, version)

	if *dryRun {
		fmt.Println("🔍 DRY RUN MODE - No files will be modified")
	}

	fmt.Printf("📁 Input Directory: %s\n", *pluginDir)
	if *outputDir != *pluginDir {
		fmt.Printf("📁 Output Directory: %s\n", *outputDir)
	}
	fmt.Println()

	// Perform migration
	result, err := migrator.Migrate()
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Print results
	printMigrationResults(result, *dryRun)

	if *dryRun {
		fmt.Println("\n✨ Dry run completed. Use --apply to perform actual migration.")
	} else {
		fmt.Println("\n✅ Migration completed successfully!")
		if result.BackupDir != "" {
			fmt.Printf("📦 Backup created: %s\n", result.BackupDir)
		}
	}
}

func parseExcludeDirs(exclude string) []string {
	if exclude == "" {
		return []string{}
	}

	dirs := []string{}
	for _, dir := range filepath.SplitList(exclude) {
		if dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

func printMigrationResults(result *migrate.Result, dryRun bool) {
	fmt.Printf("📊 Migration Summary:\n")
	fmt.Printf("  Files processed: %d\n", result.FilesProcessed)
	fmt.Printf("  Files modified: %d\n", result.FilesModified)
	fmt.Printf("  Errors: %d\n", len(result.Errors))
	fmt.Printf("  Warnings: %d\n", len(result.Warnings))
	fmt.Println()

	if len(result.Changes) > 0 {
		verb := "Changes made"
		if dryRun {
			verb = "Changes that would be made"
		}
		fmt.Printf("📝 %s:\n", verb)
		for _, change := range result.Changes {
			fmt.Printf("  %s: %s\n", change.File, change.Description)
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  Warnings:\n")
		for _, warning := range result.Warnings {
			fmt.Printf("  %s: %s\n", warning.File, warning.Message)
		}
		fmt.Println()
	}

	if len(result.Errors) > 0 {
		fmt.Printf("❌ Errors:\n")
		for _, err := range result.Errors {
			fmt.Printf("  %s: %s\n", err.File, err.Message)
		}
		fmt.Println()
	}

	if len(result.SkippedFiles) > 0 {
		fmt.Printf("⏭️  Skipped files:\n")
		for _, file := range result.SkippedFiles {
			fmt.Printf("  %s: %s\n", file.Path, file.Reason)
		}
		fmt.Println()
	}
}
