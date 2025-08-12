# ``VLOAuthProvider``

A comprehensive Swift library for OAuth 1.0 authentication with RFC 5849 compliance.

## Overview

VLOAuthProvider is a complete implementation of the OAuth 1.0 authentication protocol as specified in RFC 5849. It provides a clean, protocol-oriented API for creating digitally signed HTTP requests with support for all standard OAuth 1.0 signature methods.

### Key Features

- **Complete OAuth 1.0 Implementation**: Full support for RFC 5849 specification
- **Multiple Signature Methods**: HMAC-SHA1, PLAINTEXT, and RSA-SHA1  
- **Flexible Parameter Transmission**: Query string and authorization header support
- **Protocol-Oriented Design**: Extensible architecture with clear abstractions
- **Automatic Parameter Handling**: Nonce generation, timestamp creation, and parameter normalization
- **Comprehensive Testing**: Extensive test suite with RFC compliance verification

### Quick Start

Create and use OAuth parameters for a signed request:

```swift
import VLOAuthProvider

// Create OAuth parameters
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret", 
    signatureMethod: .hmac
)

// Create provider and sign request
let provider = OAuthProvider()
let signedRequest = try await provider.createSignedRequest(
    from: originalRequest,
    with: parameters,
    as: .header
)
```

### Architecture Overview

The library is built on three main abstraction layers:

1. **Authentication Layer** - High-level interface for creating signed requests
2. **Encryption Layer** - Pluggable cryptographic implementations
3. **Parameter Layer** - OAuth parameter management and serialization

## Topics

### Getting Started

- <doc:OAuth-Fundamentals>
- <doc:Creating-Your-First-Request>
- <doc:Signature-Methods-Guide>

### Core Components

- ``OAuthProvider``
- ``OAuthParameters``
- ``AuthenticationProvider``

### Parameter Transmission

- ``ParameterTransmissionType``

### Signature Methods

- ``OAuthSignatureMethod``
- ``EncryptionHandler``

### Error Handling

- ``EncryptionError``

### Supporting Types

- ``OAuthParameters/OAuthQueryParameterKey``

## See Also

- [RFC 5849: The OAuth 1.0 Protocol](https://tools.ietf.org/html/rfc5849)
- [OAuth 1.0 Guide](https://oauth.net/1/)