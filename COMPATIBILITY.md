# Gibson Plugin SDK Compatibility Matrix

This document outlines the compatibility between Gibson Plugin SDK versions and Gibson Framework versions, providing clear guidance for plugin developers and framework users.

## Overview

The Gibson Plugin SDK follows [Semantic Versioning (SemVer)](https://semver.org/) principles to ensure predictable compatibility:

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Current SDK Version

**Latest SDK Version**: `v1.0.0`

**Status**: Stable Release

## Compatibility Matrix

### SDK v1.0.x Compatibility

| SDK Version | Framework Version | Compatibility Level | Status | Notes |
|------------|-------------------|-------------------|---------|--------|
| 1.0.x | 2.0.x - 2.99.x | ✅ **Full** | Recommended | Optimal performance and feature support |
| 1.0.x | 1.5.x - 1.99.x | ⚠️ **Limited** | Supported | Consider framework upgrade |
| 1.0.x | 1.0.x - 1.4.x | ❌ **Deprecated** | Unsupported | Security vulnerabilities - upgrade required |
| 1.0.x | < 1.0.0 | ❌ **Incompatible** | Unsupported | Not compatible |

### Future SDK Versions

| SDK Version | Framework Version | Compatibility Level | Status | Notes |
|------------|-------------------|-------------------|---------|--------|
| 1.1.x | 2.1.x - 2.99.x | ✅ **Full** | Planned | Enhanced features and performance |
| 1.1.x | 2.0.x | ⚠️ **Limited** | Planned | Basic compatibility maintained |
| 2.0.x | 3.0.x+ | ✅ **Full** | Future | Next-generation compatibility |

## Compatibility Levels Explained

### ✅ Full Compatibility
- All SDK features work seamlessly with the framework
- No known issues or limitations
- Optimal performance and security
- **Recommended** for production use

### ⚠️ Limited Compatibility
- Core functionality works but some advanced features may be unavailable
- Potential performance limitations
- Regular testing recommended
- **Acceptable** for development and testing

### ❌ Deprecated
- Contains known security vulnerabilities
- May have functional limitations
- **Not recommended** for any use
- **Immediate upgrade required**

### ❌ Incompatible
- SDK will not function with the framework version
- **Cannot be used** together

## Version Check Tool

Use the built-in compatibility checker to verify version compatibility:

```go
import "github.com/gibson-sec/gibson-plugin-sdk/internal/version"

checker := version.NewCompatibilityChecker()
result := checker.CheckCompatibility("1.0.0", "2.0.0")

if result.IsOk() {
    compat := result.Unwrap()
    if compat.IsCompatible() {
        fmt.Println("✅ Versions are compatible")
    } else {
        fmt.Printf("❌ Incompatible: %s\n", compat.Message)
        fmt.Printf("Recommendation: %s\n", compat.GetRecommendation())
    }
}
```

## Migration Guides

### Upgrading from Framework v1.x to v2.x

**Required for**: SDK v1.0.x users on Framework v1.5.x or older

#### Before You Start
1. **Backup your configuration** and plugin data
2. **Test in development environment** first
3. **Review breaking changes** in Framework v2.0 changelog

#### Step-by-Step Migration

1. **Update Framework Dependencies**
   ```bash
   go mod edit -require github.com/gibson-sec/gibson-framework@v2.0.0
   go mod tidy
   ```

2. **Update Plugin Configuration**
   - Framework v2.x introduces new configuration schema
   - Update `gibson.yaml` configuration files
   - Migrate database schemas if applicable

3. **Test Plugin Compatibility**
   ```bash
   # Run SDK compatibility tests
   go test ./... -tags=compatibility

   # Validate plugin functionality
   gibson plugin validate --all
   ```

4. **Update Deployment Scripts**
   - Update Docker images to use Framework v2.x
   - Update Kubernetes manifests
   - Update CI/CD pipelines

#### Common Migration Issues

**Authentication Changes**
- Framework v2.x uses updated authentication mechanisms
- Update API keys and credential configurations
- Test authentication flows after migration

**Database Schema Changes**
- Run database migrations: `gibson migrate --to-version 2.0`
- Backup data before migration
- Verify data integrity after migration

**Plugin API Changes**
- Review plugin interface changes in Framework v2.x
- Update any custom plugin implementations
- Test all plugin integrations

### Upgrading Framework v1.0-1.4.x (Security Critical)

**⚠️ URGENT**: Framework versions 1.0.x through 1.4.x contain critical security vulnerabilities.

#### Immediate Actions Required

1. **Stop using deprecated versions immediately**
2. **Upgrade to Framework v2.0+ as soon as possible**
3. **Review security logs** for potential exploitation
4. **Rotate credentials** and API keys

#### Quick Upgrade Path

```bash
# Emergency upgrade
go mod edit -require github.com/gibson-sec/gibson-framework@v2.0.0
go mod tidy

# Run security audit
gibson security audit --full

# Update all credentials
gibson credentials rotate --all
```

#### Security Vulnerabilities in v1.0-1.4.x

- **CVE-2024-XXXX**: Authentication bypass vulnerability
- **CVE-2024-YYYY**: SQL injection in plugin loader
- **CVE-2024-ZZZZ**: Remote code execution via malformed payloads

**Impact**: Potential data breach, unauthorized access, system compromise

### Plugin-Specific Migration

#### For Plugin Developers

**Migrating Plugin Code**

1. **Update SDK Import**
   ```go
   // Old import (if using shared package)
   import "github.com/gibson-sec/gibson-framework/shared"

   // New SDK import
   import "github.com/gibson-sec/gibson-plugin-sdk/pkg/plugin"
   ```

2. **Update Interface Implementation**
   ```go
   // Ensure your plugin implements the latest SecurityPlugin interface
   type MyPlugin struct {
       plugin.BasePlugin
   }

   func (p *MyPlugin) Execute(ctx context.Context, request models.AssessRequest) models.Result[models.AssessResponse] {
       // Implementation using Result[T] pattern
   }
   ```

3. **Test with Migration Tool**
   ```bash
   # Use automatic migration tool (Task 14)
   gibson-migrate --plugin-dir ./plugins --dry-run
   gibson-migrate --plugin-dir ./plugins --apply
   ```

## Troubleshooting

### Common Compatibility Issues

#### Issue: "Plugin failed to load - version mismatch"
**Solution**: Check compatibility matrix and upgrade to compatible versions

#### Issue: "gRPC connection failed"
**Solution**: Ensure both SDK and Framework support the same gRPC protocol version

#### Issue: "Database schema mismatch"
**Solution**: Run database migrations for the target framework version

#### Issue: "Authentication failed after upgrade"
**Solution**: Update credentials and API configurations for new framework version

### Getting Help

1. **Check the Compatibility Matrix** (this document)
2. **Run the Version Checker Tool**
3. **Review Migration Guides**
4. **Check GitHub Issues**: [Gibson Framework Issues](https://github.com/gibson-sec/gibson-framework/issues)
5. **Community Support**: [Gibson Discord](https://discord.gg/gibson-security)

### Reporting Compatibility Issues

Found a compatibility issue not covered here? Please report it:

1. **Use the issue template**: [Report Compatibility Issue](https://github.com/gibson-sec/gibson-plugin-sdk/issues/new?template=compatibility-issue.md)
2. **Include version information**:
   - SDK version
   - Framework version
   - Operating system
   - Error messages
3. **Provide reproduction steps**
4. **Include configuration files** (remove sensitive data)

## Version Support Policy

### Support Lifecycle

- **Current Release (1.0.x)**: Full support including security updates
- **Previous Major (0.x.x)**: Security updates only for 6 months
- **End of Life**: No support, upgrade required

### Security Update Policy

- **Critical vulnerabilities**: Patched within 24-48 hours
- **High severity**: Patched within 1 week
- **Medium/Low severity**: Patched in next minor release

### Deprecation Notice

Framework versions reaching end-of-life will receive **90 days advance notice** before support termination.

## Testing Your Setup

### Automated Compatibility Testing

Include this in your CI/CD pipeline:

```yaml
# .github/workflows/compatibility.yml
name: Compatibility Check
on: [push, pull_request]

jobs:
  compatibility:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.21'

      - name: Check SDK Compatibility
        run: |
          go run github.com/gibson-sec/gibson-plugin-sdk/cmd/version-check \
            --sdk-version $(go list -m github.com/gibson-sec/gibson-plugin-sdk | cut -d' ' -f2) \
            --framework-version $(go list -m github.com/gibson-sec/gibson-framework | cut -d' ' -f2)
```

### Manual Testing Checklist

Before deploying with new versions:

- [ ] ✅ Run version compatibility check
- [ ] ✅ Test plugin loading and initialization
- [ ] ✅ Verify gRPC communication works
- [ ] ✅ Test core plugin functionality
- [ ] ✅ Validate security assessment results
- [ ] ✅ Check performance benchmarks
- [ ] ✅ Test error handling and recovery
- [ ] ✅ Verify logging and monitoring work

## Additional Resources

- [Gibson Framework Documentation](https://docs.gibson-sec.com/framework/)
- [Gibson Plugin SDK Documentation](https://docs.gibson-sec.com/sdk/)
- [Migration Tools](./cmd/migrate/)
- [Example Plugins](./examples/)
- [API Reference](./docs/API.md)
- [Security Guidelines](https://docs.gibson-sec.com/security/)

---

**Last Updated**: 2024-01-15
**Document Version**: 1.0
**Applies to SDK**: v1.0.x

For questions about this compatibility matrix, please [open an issue](https://github.com/gibson-sec/gibson-plugin-sdk/issues) or contact the Gibson Security team.