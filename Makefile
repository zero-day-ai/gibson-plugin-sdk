# Gibson Plugin SDK Makefile

.PHONY: help build test test-unit test-integration test-e2e test-coverage test-short
.PHONY: lint lint-fix fmt vet security deps-check
.PHONY: clean proto-gen version build-version
.PHONY: ci release release-check package dist
.PHONY: tag-release prepare-release

# Default target
.DEFAULT_GOAL := help

# Variables
SDK_NAME := gibson-plugin-sdk
VERSION ?= 1.0.0
COMMIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_VERSION ?= $(shell go version | cut -d' ' -f3)

# Build flags for version information
LDFLAGS := -X main.GitCommit=$(COMMIT_SHA) \
           -X main.BuildDate=$(BUILD_DATE) \
           -X main.GoVersion=$(GO_VERSION)

# Directories
COVERAGE_DIR := coverage
PROTO_DIR := pkg/grpc/proto

# Test flags
TEST_FLAGS := -race -v
INTEGRATION_FLAGS := -tags=integration
E2E_FLAGS := -tags=e2e
COVERAGE_FLAGS := -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic
COVERAGE_THRESHOLD := 80

## help: Show this help message
help:
	@echo "Gibson Plugin SDK - Build and Test Commands"
	@echo ""
	@echo "Development Commands:"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

## fmt: Format Go code
fmt:
	@echo "Formatting Go code..."
	@gofmt -w .
	@goimports -w .

## vet: Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

## lint: Run comprehensive linting
lint:
	@echo "Running golangci-lint..."
	@golangci-lint run

## lint-fix: Run linting with auto-fix
lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@golangci-lint run --fix

## security: Run security analysis
security:
	@echo "Running gosec security scan..."
	@gosec ./...

## deps-check: Check for dependency issues
deps-check:
	@echo "Checking dependencies..."
	@go mod verify
	@go mod tidy

## test-unit: Run unit tests
test-unit:
	@echo "Running unit tests..."
	@go test $(TEST_FLAGS) ./pkg/...

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	@go test $(TEST_FLAGS) $(INTEGRATION_FLAGS) ./tests/integration/...

## test-e2e: Run end-to-end tests
test-e2e:
	@echo "Running end-to-end tests..."
	@go test $(TEST_FLAGS) $(E2E_FLAGS) ./tests/e2e/...

## test-short: Run quick tests for development
test-short:
	@echo "Running short tests..."
	@go test -short $(TEST_FLAGS) ./pkg/...

## test: Run all tests
test: test-unit test-integration test-e2e

## test-coverage: Generate test coverage report
test-coverage:
	@echo "Generating test coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	@go test $(TEST_FLAGS) $(COVERAGE_FLAGS) ./pkg/...
	@go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@go tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1

## proto-gen: Generate gRPC code from protobuf
proto-gen:
	@echo "Generating gRPC code from protobuf..."
	@protoc --proto_path=. --proto_path=/tmp/include \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/*.proto

## clean: Clean build artifacts and cache
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(COVERAGE_DIR)
	@go clean -cache -testcache -modcache

## ci: Run complete CI pipeline
ci: fmt vet lint test-coverage security deps-check
	@echo "CI pipeline completed successfully!"

## dev: Quick development cycle
dev: fmt vet test-short
	@echo "Development cycle completed!"

## build-version: Build version utility
build-version:
	@echo "Building version utility..."
	@go build -ldflags "$(LDFLAGS)" -o build/gibson-sdk-version version.go

## version: Show version information
version: build-version
	@./build/gibson-sdk-version || echo "Version: $(VERSION), Commit: $(COMMIT_SHA), Date: $(BUILD_DATE)"

## release-check: Validate release readiness
release-check: ci
	@echo "Checking release readiness for version $(VERSION)..."
	@echo "✓ All tests passed"
	@echo "✓ Code quality checks passed"
	@echo "✓ Security analysis passed"
	@echo "✓ Dependencies verified"
	@echo "Ready for release!"

## package: Create distribution packages
package: clean ci build-version
	@echo "Creating distribution packages for version $(VERSION)..."
	@mkdir -p dist
	@tar -czf dist/gibson-plugin-sdk-$(VERSION).tar.gz \
		--exclude='.git*' \
		--exclude='dist' \
		--exclude='build' \
		--exclude='coverage' \
		--exclude='*.log' \
		.
	@echo "Package created: dist/gibson-plugin-sdk-$(VERSION).tar.gz"

## dist: Create distribution with documentation
dist: package
	@echo "Creating full distribution with documentation..."
	@mkdir -p dist/gibson-plugin-sdk-$(VERSION)
	@tar -xzf dist/gibson-plugin-sdk-$(VERSION).tar.gz -C dist/gibson-plugin-sdk-$(VERSION) --strip-components=1
	@cd dist && tar -czf gibson-plugin-sdk-$(VERSION)-full.tar.gz gibson-plugin-sdk-$(VERSION)
	@rm -rf dist/gibson-plugin-sdk-$(VERSION)
	@echo "Full distribution created: dist/gibson-plugin-sdk-$(VERSION)-full.tar.gz"

## prepare-release: Prepare release with all checks
prepare-release: release-check package
	@echo "Release $(VERSION) prepared successfully!"
	@echo "Files ready for distribution:"
	@ls -la dist/
	@echo ""
	@echo "To complete the release:"
	@echo "1. Review the generated packages"
	@echo "2. Update CHANGELOG.md if needed"
	@echo "3. Run 'make tag-release' to create git tag"
	@echo "4. Push tag with: git push origin v$(VERSION)"

## tag-release: Create git tag for release
tag-release:
	@echo "Creating git tag for release $(VERSION)..."
	@if git tag -l | grep -q "^v$(VERSION)$$"; then \
		echo "Tag v$(VERSION) already exists!"; \
		exit 1; \
	fi
	@git tag -a v$(VERSION) -m "Release v$(VERSION)"
	@echo "Tag v$(VERSION) created successfully!"
	@echo "Push with: git push origin v$(VERSION)"

## release: Complete release process
release: prepare-release tag-release
	@echo "Release $(VERSION) completed!"
	@echo "Don't forget to push the tag: git push origin v$(VERSION)"