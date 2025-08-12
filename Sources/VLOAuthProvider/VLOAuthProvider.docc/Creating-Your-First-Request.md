# Creating Your First OAuth Request

A step-by-step guide to creating your first signed OAuth request using VLOAuthProvider.

## Prerequisites

Before creating OAuth requests, you'll need:

- Consumer key and consumer secret from your OAuth service provider
- The API endpoint URL you want to access
- Basic understanding of the OAuth 1.0 flow

## Step 1: Import VLOAuthProvider

```swift
import VLOAuthProvider
import Foundation
```

## Step 2: Create OAuth Parameters

Create an ``OAuthParameters`` instance with your consumer credentials:

```swift
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    signatureMethod: .hmac
)
```

### Parameter Options

- **Consumer Key/Secret**: Your app's credentials from the service provider
- **Signature Method**: Choose `.hmac` for most services, `.rsa` for enterprise setups
- **Nonce/Timestamp**: Automatically generated for security

## Step 3: Create the Original Request

Build your HTTP request as you normally would:

```swift
var request = URLRequest(url: URL(string: "https://api.example.com/1.1/account/verify_credentials.json")!)
request.httpMethod = "GET"
request.addValue("application/json", forHTTPHeaderField: "Accept")
```

## Step 4: Create OAuth Provider

Initialize the OAuth provider:

```swift
let provider = OAuthProvider()
```

## Step 5: Sign the Request

Use the provider to create a signed request:

```swift
do {
    let signedRequest = try await provider.createSignedRequest(
        from: request,
        with: parameters,
        as: .header  // Recommended: use authorization header
    )
    
    // Use signedRequest for your API call
    let (data, response) = try await URLSession.shared.data(for: signedRequest)
    
} catch {
    print("OAuth signing failed: \(error)")
}
```

## Parameter Transmission Methods

VLOAuthProvider supports different ways to include OAuth parameters:

### Authorization Header (Recommended)

```swift
let signedRequest = try await provider.createSignedRequest(
    from: request,
    with: parameters,
    as: .header
)
```

**Pros**: Clean URLs, parameters not visible in logs
**Cons**: More complex HTTP headers

### Query String

```swift
let signedRequest = try await provider.createSignedRequest(
    from: request,
    with: parameters,
    as: .queryString
)
```

**Pros**: Simple, visible for debugging
**Cons**: Parameters visible in URLs and logs

## Complete Example

Here's a complete example that puts it all together:

```swift
import VLOAuthProvider
import Foundation

class TwitterAPIClient {
    private let provider = OAuthProvider()
    private let consumerKey = "your-consumer-key"
    private let consumerSecret = "your-consumer-secret"
    
    func verifyCredentials() async throws -> Data {
        // Create OAuth parameters
        let parameters = OAuthParameters(
            consumerKey: consumerKey,
            consumerSecret: consumerSecret,
            signatureMethod: .hmac
        )
        
        // Create original request
        var request = URLRequest(
            url: URL(string: "https://api.twitter.com/1.1/account/verify_credentials.json")!
        )
        request.httpMethod = "GET"
        request.addValue("application/json", forHTTPHeaderField: "Accept")
        
        // Sign the request
        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: parameters,
            as: .header
        )
        
        // Make the API call
        let (data, _) = try await URLSession.shared.data(for: signedRequest)
        return data
    }
}
```

## With Access Tokens

For requests that require user access tokens:

```swift
let parameters = OAuthParameters(
    consumerKey: "your-consumer-key",
    consumerSecret: "your-consumer-secret",
    requestToken: "user-access-token",
    requestSecret: "user-access-token-secret",
    signatureMethod: .hmac
)
```

## Error Handling

Handle common OAuth errors:

```swift
do {
    let signedRequest = try await provider.createSignedRequest(
        from: request,
        with: parameters,
        as: .header
    )
} catch let error as EncryptionError {
    switch error {
    case .emptyKey:
        print("Missing consumer secret")
    case .emptyMessage:
        print("Invalid request parameters")
    case .signingFailed:
        print("Cryptographic signing failed")
    default:
        print("Other encryption error: \(error)")
    }
} catch {
    print("Request error: \(error)")
}
```

## Next Steps

- Learn about different <doc:Signature-Methods-Guide>
- Understand the complete OAuth 1.0 flow in <doc:OAuth-Fundamentals>
- Explore advanced parameter configuration in ``OAuthParameters``

## See Also

- ``OAuthProvider``
- ``OAuthParameters``
- ``ParameterTransmissionType``
- ``EncryptionError``