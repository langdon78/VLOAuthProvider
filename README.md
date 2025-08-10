# VL (Very Light 🪶) OAuth Provider

A lightweight, RFC 5849 compliant OAuth 1.0 implementation for Swift, supporting all three required signature methods (HMAC-SHA1, RSA-SHA1, PLAINTEXT) with modern async/await API.

## Features

- ✅ **RFC 5849 Compliant** - Full OAuth 1.0 specification support
- ✅ **All Signature Methods** - HMAC-SHA1, RSA-SHA1, and PLAINTEXT
- ✅ **Multiple Transmission Types** - Query string and Authorization header
- ✅ **Modern Swift** - async/await API with proper error handling
- ✅ **Thread Safe** - Concurrent request signing support
- ✅ **Comprehensive Testing** - 64 unit tests with RFC compliance verification
- ✅ **Server Implementation** - Complete OAuth 1.0 server-side support

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/yourusername/VLOAuthProvider.git", from: "1.0.0")
]
```

## Quick Start

```swift
import VLOAuthProvider

// Create OAuth parameters
let params = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    signatureMethod: .hmac
)

// Create and sign a request
let provider = OAuthProvider()
let originalRequest = URLRequest(url: URL(string: "https://api.example.com/data")!)

let signedRequest = try await provider.createSignedRequest(
    from: originalRequest,
    with: params,
    as: .queryString
)
```

## API Documentation

### OAuthProvider

`OAuthProvider` is the main class for handling OAuth 1.0 authentication according to RFC 5849. It provides functionality to sign HTTP requests using the OAuth 1.0 protocol with support for multiple signature methods and parameter transmission types.

#### Class Declaration

```swift
public class OAuthProvider: AuthenticationProvider
```

#### Initialization

##### `init()`

Creates a new instance of `OAuthProvider` with default configuration.

```swift
public init()
```

**Usage:**
```swift
let provider = OAuthProvider()
```

#### Public Methods

##### `createSignedRequest(from:with:as:)`

The primary method for creating OAuth 1.0 signed requests. This is an asynchronous method that generates and applies an OAuth signature to the provided request.

```swift
public func createSignedRequest(
    from request: URLRequest,
    with parameters: OAuthParameters,
    as transmissionType: ParameterTransmissionType
) async throws -> URLRequest
```

**Parameters:**
- `request`: The original `URLRequest` to be signed
- `parameters`: An `OAuthParameters` instance containing OAuth credentials and settings
- `transmissionType`: How OAuth parameters should be transmitted (`.header`, `.queryString`, or `.formData`)

**Returns:** A new `URLRequest` with OAuth signature applied

**Throws:** 
- `URLError(.badURL)` if the request URL is invalid or missing HTTP method
- `EncryptionError` if signature generation fails
- Various errors from the underlying encryption handlers

**Usage Examples:**

```swift
// Query String transmission
let provider = OAuthProvider()
let params = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    signatureMethod: .hmac
)

let signedRequest = try await provider.createSignedRequest(
    from: originalRequest,
    with: params,
    as: .queryString
)

// Authorization Header transmission
let signedRequest = try await provider.createSignedRequest(
    from: originalRequest,
    with: params,
    as: .header
)
```

### OAuthParameters

Manages OAuth parameter lifecycle including consumer credentials, tokens, nonces, and timestamps.

```swift
let params = OAuthParameters(
    consumerKey: "your-key",
    consumerSecret: "your-secret",
    requestToken: "user-token",        // Optional
    requestSecret: "user-secret",      // Optional  
    signatureMethod: .hmac,
    nonce: "unique-nonce",             // Auto-generated if not provided
    timestamp: "1234567890",           // Auto-generated if not provided
    callback: callbackURL,             // Optional
    verifier: "oauth-verifier"         // Optional
)
```

### Supported Signature Methods

The `OAuthProvider` supports all three RFC 5849 required signature methods:

#### HMAC-SHA1 (`.hmac`)
- Most commonly used method
- Uses consumer secret and token secret to create HMAC-SHA1 signature
- Provides good security with shared secrets

#### PLAINTEXT (`.plaintext`)
- Simple concatenation of secrets
- **Requires HTTPS transport** for security
- Used for testing or when cryptographic operations are not feasible

#### RSA-SHA1 (`.rsa`)
- Uses RSA private key for signing
- Provides public key cryptography benefits
- Requires RSA private key in `OAuthParameters.rsaPrivateKey`

### Parameter Transmission Types

#### Query String (`.queryString`)
OAuth parameters are appended to the request URL as query parameters.

**Example:**
```
https://api.example.com/endpoint?oauth_consumer_key=key&oauth_signature=sig...
```

#### Authorization Header (`.header`)
OAuth parameters are included in the HTTP Authorization header.

**Example:**
```
Authorization: OAuth oauth_consumer_key="key", oauth_signature="sig"...
```

#### Form Data (`.formData`)
*Currently not supported* - will cause a fatal error if used.

## Advanced Usage

### Using Different Signature Methods

```swift
// HMAC-SHA1 (most common)
let hmacParams = OAuthParameters(
    consumerKey: "key",
    consumerSecret: "secret",
    signatureMethod: .hmac
)

// RSA-SHA1 (requires private key)
let rsaParams = OAuthParameters(
    consumerKey: "key",
    consumerSecret: "secret",
    signatureMethod: .rsa
)
rsaParams.rsaPrivateKey = "-----BEGIN PRIVATE KEY-----\n..."

// PLAINTEXT (requires HTTPS)
let plaintextParams = OAuthParameters(
    consumerKey: "key",
    consumerSecret: "secret",
    signatureMethod: .plaintext
)
```

### OAuth 1.0 Three-Legged Flow

```swift
// Step 1: Request temporary credentials
let tempParams = OAuthParameters(
    consumerKey: "your-key",
    consumerSecret: "your-secret",
    signatureMethod: .hmac,
    callback: URL(string: "your-app://callback")
)

let tempRequest = URLRequest(url: URL(string: "https://api.example.com/oauth/request_token")!)
let signedTempRequest = try await provider.createSignedRequest(
    from: tempRequest,
    with: tempParams,
    as: .header
)

// Step 2: Direct user to authorization URL
// https://api.example.com/oauth/authorize?oauth_token=temp_token

// Step 3: Exchange for access token
let accessParams = OAuthParameters(
    consumerKey: "your-key",
    consumerSecret: "your-secret",
    requestToken: "temp_token",
    requestSecret: "temp_secret",
    signatureMethod: .hmac,
    verifier: "oauth_verifier_from_callback"
)

let accessRequest = URLRequest(url: URL(string: "https://api.example.com/oauth/access_token")!)
let signedAccessRequest = try await provider.createSignedRequest(
    from: accessRequest,
    with: accessParams,
    as: .header
)
```

## Error Handling

The `OAuthProvider` throws various errors during operation:

- **`URLError(.badURL)`**: Invalid or missing URL/HTTP method
- **`EncryptionError.emptyMessage`**: Empty signature base string
- **`EncryptionError.emptyKey`**: Empty signing key
- **`EncryptionError.unexpectedHashType`**: Unsupported hash algorithm
- **`EncryptionError.invalidPrivateKey`**: Invalid RSA private key (RSA-SHA1 only)
- **`EncryptionError.encodingError`**: String encoding failure
- **`EncryptionError.signingFailed`**: Cryptographic operation failure

```swift
do {
    let signedRequest = try await provider.createSignedRequest(
        from: request,
        with: parameters,
        as: .header
    )
    // Use signed request
} catch let error as EncryptionError {
    print("Encryption error: \(error)")
} catch {
    print("Other error: \(error)")
}
```

## Thread Safety

The `OAuthProvider` class is thread-safe and can be used concurrently from multiple threads. All methods are asynchronous and designed for concurrent access.

## Performance Considerations

- OAuth signature generation involves cryptographic operations
- HMAC-SHA1 is generally faster than RSA-SHA1
- Consider caching `OAuthProvider` instances for repeated use
- Signature generation is CPU-intensive; avoid generating signatures unnecessarily

## RFC 5849 Compliance

The `OAuthProvider` implementation strictly follows RFC 5849 specifications:

- ✅ Proper signature base string construction (Section 3.4.1)
- ✅ RFC 3986 percent encoding (Section 3.6)
- ✅ Parameter normalization and sorting (Section 3.4.1.3.2)
- ✅ All three required signature methods (Section 3.4)
- ✅ Proper Authorization header formatting (Section 3.5.1)
- ✅ Query parameter transmission (Section 3.5.2)

## Testing

Run the comprehensive test suite:

```bash
swift test
```

The package includes 64 unit tests covering:
- All signature methods
- Parameter encoding and transmission
- Error handling
- RFC compliance verification
- Edge cases and Unicode support
- Performance benchmarks

## Requirements

- Swift 5.7+
- iOS 16.0+ / macOS 13.0+ / tvOS 16.0+ / watchOS 6.0+

## Dependencies

- [swift-collections](https://github.com/apple/swift-collections) - For deterministic parameter ordering

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
