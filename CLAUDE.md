# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building and Testing
```bash
# Build the package
swift build

# Run all tests
swift test

# Run tests for a specific test case
swift test --filter OAuthProviderTests

# Run a single test method
swift test --filter testHMACSHA1SignatureGeneration

# Build in release mode
swift build -c release

# Clean build artifacts
swift package clean
```

### Package Management
```bash
# Update dependencies
swift package update

# Reset package to clean state
swift package reset

# Generate Xcode project (if needed)
swift package generate-xcodeproj
```

## Architecture

### Core Design Pattern
VLOAuthProvider implements OAuth 1.0 (RFC 5849) using a **protocol-oriented architecture** with three main abstraction layers:

1. **Authentication Layer** (`AuthenticationProvider` protocol) - High-level interface for creating signed requests
2. **Encryption Layer** (`EncryptionHandler` protocol) - Pluggable cryptographic implementations 
3. **Parameter Layer** (`OAuthParameters` struct) - OAuth parameter management and serialization

### Key Components

**OAuthProvider** (main class implementing `AuthenticationProvider`)
- Handles OAuth 1.0 signature generation and request signing
- Supports three parameter transmission methods: query string, authorization header, form data
- Uses dependency injection for encryption handlers

**Encryption Handlers**
- `HMACEncryptionHandler` - HMAC-SHA1, MD5, SHA256, SHA512 support using CommonCrypto
- `RSAEncryptionHandler` - RSA-SHA1 signatures using Security framework
- All handlers conform to `EncryptionHandler` protocol for swappable implementations

**OAuthParameters**
- Manages OAuth parameter lifecycle (consumer credentials, tokens, nonces, timestamps)
- Uses `OrderedDictionary` from swift-collections for deterministic parameter ordering
- Handles RFC 3986 URL encoding requirements automatically

**Server Implementation** (OAuth 1.0 three-legged flow)
- `OAuthServer` - Complete server-side OAuth 1.0 implementation
- `OAuthServerDelegate` - Protocol for integrating with storage/validation systems
- Handles temporary credentials, authorization, and token exchange endpoints

### Signature Methods
The package implements all three RFC 5849 required signature methods:
- **HMAC-SHA1** - Most common, uses shared secrets
- **PLAINTEXT** - Simple concatenation, requires HTTPS
- **RSA-SHA1** - Public key cryptography, uses private key signing

### Parameter Transmission
OAuth parameters can be transmitted via:
- **Query String** (`.queryString`) - Parameters appended to URL
- **Authorization Header** (`.header`) - Parameters in HTTP Authorization header
- **Form Data** (`.formData`) - Parameters in request body (not yet implemented)

### Error Handling
- `EncryptionError` enum for cryptographic failures
- `OAuthServerError` enum for server-side validation failures
- All methods use Swift's `throws` pattern for error propagation

### Testing Strategy
- Uses Swift Testing framework (`@Test` syntax)
- Comprehensive test coverage including RFC compliance verification
- Known test vectors from RFC 2202 for HMAC validation
- Performance benchmarks included
- Mock implementations for integration testing

### Dependencies
- **swift-collections** - For `OrderedDictionary` in parameter management
- **CommonCrypto** - For HMAC implementations
- **Security** - For RSA signature operations

### RFC 5849 Compliance
The implementation follows OAuth 1.0 specification strictly:
- Proper signature base string construction
- RFC 3986 percent encoding
- Nonce generation and replay protection
- Timestamp validation windows
- Parameter normalization and sorting