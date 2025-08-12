# Signature Methods Guide

Understanding and choosing the right OAuth signature method for your application.

## Overview

OAuth 1.0 supports three signature methods, each with different security characteristics and implementation requirements. VLOAuthProvider supports all three methods through the ``OAuthSignatureMethod`` enumeration.

## HMAC-SHA1 Signature Method

The most commonly used OAuth signature method.

### How It Works

HMAC-SHA1 uses a hash-based message authentication code with the SHA-1 algorithm. It combines your consumer secret and token secret to create a signing key.

**Signing Key Format**: `consumer_secret&token_secret`

### Usage

```swift
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    signatureMethod: .hmac
)
```

For requests with access tokens:

```swift
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    requestToken: "access-token",
    requestSecret: "access-token-secret",
    signatureMethod: .hmac
)
```

### Security Characteristics

- ✅ **High Security**: Cryptographically secure
- ✅ **Widely Supported**: Accepted by all OAuth 1.0 services
- ✅ **Performance**: Fast computation
- ✅ **Transport**: Works over HTTP or HTTPS

### When to Use

- **Most applications**: Default choice for OAuth 1.0
- **Production systems**: Reliable and secure
- **Service compatibility**: When maximum compatibility is needed

## PLAINTEXT Signature Method

A simple signature method that uses raw secrets without cryptographic hashing.

### How It Works

PLAINTEXT simply concatenates the consumer secret and token secret with an ampersand. No hashing or encryption is performed.

**Signature Format**: `consumer_secret&token_secret`

### Usage

```swift
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    signatureMethod: .plaintext
)
```

### Security Characteristics

- ⚠️ **Low Security**: Secrets transmitted in plaintext
- ⚠️ **HTTPS Required**: Must use secure transport
- ✅ **Performance**: Fastest method
- ✅ **Debugging**: Easy to inspect and verify

### When to Use

- **Development/Testing**: Easy debugging and verification
- **HTTPS Environments**: When secure transport is guaranteed
- **Performance Critical**: When minimal computational overhead is required

**⚠️ Warning**: Never use PLAINTEXT over unencrypted HTTP connections.

## RSA-SHA1 Signature Method

A public key cryptography signature method using RSA keys with SHA-1 hashing.

### How It Works

RSA-SHA1 uses your private RSA key to sign the signature base string. The service provider uses your public key to verify the signature.

### Setup

First, generate an RSA key pair:

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key  
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

Register your public key with the OAuth service provider, then use the private key for signing:

```swift
let privateKeyPEM = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----
"""

var parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "not-used-for-rsa",
    signatureMethod: .rsa
)
parameters.rsaPrivateKey = privateKeyPEM
```

### Security Characteristics

- ✅ **Highest Security**: Public key cryptography
- ✅ **Non-repudiation**: Signatures can't be forged
- ✅ **Key Management**: No shared secrets
- ⚠️ **Complexity**: Requires key pair management

### When to Use

- **Enterprise Applications**: When highest security is required
- **PKI Environments**: When you have existing key management
- **Long-term Credentials**: When key rotation is well-managed
- **High-value Transactions**: When non-repudiation is important

## Choosing the Right Method

### Decision Matrix

| Factor | HMAC-SHA1 | PLAINTEXT | RSA-SHA1 |
|--------|-----------|-----------|----------|
| **Security Level** | High | Low | Highest |
| **Implementation Complexity** | Low | Lowest | High |
| **Performance** | Fast | Fastest | Slow |
| **Key Management** | Simple | Simple | Complex |
| **Transport Requirements** | Any | HTTPS Only | Any |
| **Service Support** | Universal | Most | Limited |

### Recommendations

**For Most Applications**: Use **HMAC-SHA1**
- Good security with simple implementation
- Universal service provider support
- Reasonable performance characteristics

**For Development/Testing**: Use **PLAINTEXT** (over HTTPS)
- Easy to debug and verify
- Minimal computational overhead
- Quick prototyping

**For Enterprise/High-Security**: Use **RSA-SHA1**
- Maximum security guarantees  
- Non-repudiation of requests
- When you have PKI infrastructure

## Error Handling by Method

Different signature methods can produce different errors:

```swift
do {
    let signedRequest = try await provider.createSignedRequest(
        from: request,
        with: parameters,
        as: .header
    )
} catch EncryptionError.invalidPrivateKey {
    // RSA-SHA1 specific: malformed private key
    print("Invalid RSA private key format")
} catch EncryptionError.emptyKey {
    // All methods: missing consumer secret
    print("Consumer secret is required")
} catch EncryptionError.signingFailed {
    // Cryptographic operation failed
    print("Signature generation failed")
}
```

## Performance Considerations

Relative performance of signature methods:

1. **PLAINTEXT**: ~0.01ms (string concatenation only)
2. **HMAC-SHA1**: ~0.1ms (hash computation)
3. **RSA-SHA1**: ~1-5ms (RSA signing operation)

For high-throughput applications, consider the computational cost of signature generation.

## See Also

- ``OAuthSignatureMethod``
- ``EncryptionError``
- ``OAuthParameters``
- <doc:OAuth-Fundamentals>