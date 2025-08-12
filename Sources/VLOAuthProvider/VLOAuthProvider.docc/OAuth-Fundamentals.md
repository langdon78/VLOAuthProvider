# OAuth 1.0 Fundamentals

Understanding the OAuth 1.0 authentication protocol and how VLOAuthProvider implements it.

## What is OAuth 1.0?

OAuth 1.0 is an authentication protocol that allows applications to access user resources from web services without requiring users to share their passwords. Unlike OAuth 2.0, OAuth 1.0 uses cryptographic signatures to verify the authenticity of requests.

### Key Concepts

**Consumer (Client Application)**
: The application that wants to access protected resources. Identified by a consumer key and consumer secret.

**Service Provider** 
: The web service hosting protected resources (e.g., Twitter, Flickr).

**User (Resource Owner)**
: The person who owns the protected resources and grants access to the consumer.

**Tokens**
: Temporary credentials that represent the user's authorization for the consumer to access resources.

## OAuth 1.0 Flow

The OAuth 1.0 protocol follows a three-legged authentication flow:

### 1. Request Temporary Credentials

The consumer requests temporary credentials (request token) from the service provider:

```swift
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    signatureMethod: .hmac,
    callback: URL(string: "https://yourapp.com/oauth/callback")!
)

let signedRequest = try await provider.createSignedRequest(
    from: temporaryCredentialRequest,
    with: parameters,
    as: .header
)
```

### 2. User Authorization

The consumer redirects the user to the service provider's authorization page with the temporary credentials. The user grants or denies access.

### 3. Exchange for Access Token

After user authorization, the consumer exchanges the temporary credentials (plus verifier) for permanent access credentials:

```swift
var parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    requestToken: temporaryToken,
    requestSecret: temporarySecret,
    signatureMethod: .hmac,
    verifier: authorizationVerifier
)

let signedRequest = try await provider.createSignedRequest(
    from: accessTokenRequest,
    with: parameters,
    as: .header
)
```

## Digital Signatures

OAuth 1.0's security relies on digital signatures. Every request must include a signature that proves:

1. The request came from the legitimate consumer
2. The request hasn't been tampered with
3. The request is fresh (not a replay attack)

### Signature Base String

The signature is calculated from a normalized string containing:

- HTTP method (GET, POST, etc.)
- Request URL (normalized)
- Request parameters (sorted and encoded)

Example signature base string:
```
GET&https%3A%2F%2Fapi.example.com%2F1.1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3Dxyz%26oauth_nonce%3Dabc...
```

### Signing Key

The signing key depends on the signature method:

- **HMAC-SHA1**: `consumer_secret&token_secret`
- **PLAINTEXT**: `consumer_secret&token_secret`  
- **RSA-SHA1**: RSA private key

## VLOAuthProvider Implementation

VLOAuthProvider handles all the complex details of OAuth 1.0:

- Automatic nonce and timestamp generation
- Proper parameter encoding and normalization
- Signature base string construction
- Cryptographic signature generation
- Request modification for parameter transmission

This allows you to focus on your application logic rather than OAuth implementation details.

## Security Considerations

### Nonce and Timestamp

VLOAuthProvider automatically generates:
- **Nonce**: A cryptographically random value unique to each request
- **Timestamp**: Unix timestamp to prevent replay attacks

### Signature Methods

Choose the appropriate signature method:

- **HMAC-SHA1**: Most common, good security with shared secrets
- **PLAINTEXT**: Only for debugging, requires HTTPS
- **RSA-SHA1**: Highest security, requires private key management

### Parameter Transmission

For production applications, use authorization header transmission (`.header`) to keep OAuth parameters out of URLs and server logs.

## See Also

- ``OAuthProvider``
- ``OAuthParameters``  
- ``OAuthSignatureMethod``
- <doc:Creating-Your-First-Request>