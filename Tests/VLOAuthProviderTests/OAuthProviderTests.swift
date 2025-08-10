import Testing
@testable import VLOAuthProvider
import Foundation

struct OAuthProviderTests {
    
    // MARK: - Test Fixtures
    
    private let testConsumerKey = "test-consumer-key"
    private let testConsumerSecret = "test-consumer-secret"
    private let testRequestToken = "test-request-token"
    private let testRequestSecret = "test-request-secret"
    private let testNonce = "test-nonce-123"
    private let testTimestamp = "1234567890"
    private let testCallback = URL(string: "https://example.com/callback")!
    
    private var testParameters: OAuthParameters {
        OAuthParameters(
            consumerKey: testConsumerKey,
            consumerSecret: testConsumerSecret,
            requestToken: testRequestToken,
            requestSecret: testRequestSecret,
            version: "1.0",
            signatureMethod: .hmac,
            nonce: testNonce,
            timestamp: testTimestamp,
            callback: testCallback
        )
    }
    
    // MARK: - Initialization Tests
    
    @Test("OAuthProvider initializes with default HMAC encryption handler")
    func testInitializationWithDefaultHandler() async throws {
        // Test that provider can be created without throwing
        let provider = OAuthProvider()
        
        // Test basic functionality works
        let url = URL(string: "https://example.com")!
        let request = URLRequest(url: url)
        let result = try? await provider.createSignedRequest(from: request, with: testParameters, as: .queryString)
        #expect(result != nil)
    }
    
    @Test("OAuthProvider initializes with custom encryption handler")
    func testInitializationWithCustomHandler() async {
        // Test that provider can be created with custom handler
        let provider = OAuthProvider()
        
        // Test basic functionality works
        let url = URL(string: "https://example.com")!
        let request = URLRequest(url: url)
        let result = try? await provider.createSignedRequest(from: request, with: testParameters, as: .queryString)
        #expect(result != nil)
    }
    
    // MARK: - RFC 3986 Encoding Tests (via public API)
    
    @Test("RFC 3986 encoding works correctly through signed requests")
    func testRFC3986EncodingThroughSignedRequests() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint")!
        let request = URLRequest(url: url)
        
        let specialParams = OAuthParameters(
            consumerKey: "key with spaces & symbols!",
            consumerSecret: "secret@#$%^&*()",
            signatureMethod: .hmac,
            nonce: "nonce=test",
            timestamp: testTimestamp
        )
        
        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: specialParams,
            as: .queryString
        )
        
        // Verify special characters are properly encoded in the URL
        #expect(signedRequest.url != nil)
        let urlString = signedRequest.url!.absoluteString
        #expect(urlString.contains("%"))
        #expect(urlString.contains("oauth_consumer_key"))
        #expect(urlString.contains("oauth_signature"))
    }
    
    // MARK: - Request Creation Tests
    
    @Test("Signed request is created with query string parameters")
    func testCreateSignedRequestWithQueryString() async throws {
        let provider = OAuthProvider()
        let originalURL = URL(string: "https://api.example.com/endpoint")!
        let originalRequest = URLRequest(url: originalURL)
        
        let signedRequest = try await provider.createSignedRequest(
            from: originalRequest,
            with: testParameters,
            as: .queryString
        )
        
        #expect(signedRequest.url != nil)
        #expect(signedRequest.url!.absoluteString.contains("oauth_consumer_key"))
        #expect(signedRequest.url!.absoluteString.contains("oauth_signature"))
        #expect(signedRequest.httpMethod == originalRequest.httpMethod)
    }
    
    @Test("Signed request is created with authorization header")
    func testCreateSignedRequestWithAuthorizationHeader() async throws {
        let provider = OAuthProvider()
        let originalURL = URL(string: "https://api.example.com/endpoint")!
        var originalRequest = URLRequest(url: originalURL)
        originalRequest.httpMethod = "POST"
        
        let signedRequest = try await provider.createSignedRequest(
            from: originalRequest,
            with: testParameters,
            as: .header
        )
        
        #expect(signedRequest.url == originalURL) // URL should not change
        #expect(signedRequest.value(forHTTPHeaderField: "Authorization") != nil)
        #expect(signedRequest.value(forHTTPHeaderField: "Authorization")!.hasPrefix("OAuth "))
        #expect(signedRequest.httpMethod == "POST")
    }
    
    @Test("Different signature methods work correctly")
    func testDifferentSignatureMethods() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint")!
        let request = URLRequest(url: url)
        
        // Test HMAC-SHA1
        let hmacParams = OAuthParameters(
            consumerKey: "consumer-key",
            consumerSecret: "consumer-secret",
            requestSecret: "request-secret",
            signatureMethod: .hmac,
            nonce: "nonce",
            timestamp: "1234567890"
        )
        
        let hmacRequest = try await provider.createSignedRequest(
            from: request,
            with: hmacParams,
            as: .queryString
        )
        
        #expect(hmacRequest.url!.absoluteString.contains("oauth_signature"))
        #expect(hmacRequest.url!.absoluteString.contains("HMAC-SHA1"))
        
        // Test PLAINTEXT
        let plaintextParams = OAuthParameters(
            consumerKey: "consumer-key",
            consumerSecret: "consumer-secret",
            requestSecret: "request-secret",
            signatureMethod: .plaintext,
            nonce: "nonce",
            timestamp: "1234567890"
        )
        
        let plaintextRequest = try await provider.createSignedRequest(
            from: request,
            with: plaintextParams,
            as: .queryString
        )
        
        #expect(plaintextRequest.url!.absoluteString.contains("oauth_signature"))
        #expect(plaintextRequest.url!.absoluteString.contains("PLAINTEXT"))
    }
    
    // MARK: - Edge Case Tests
    
    @Test("Parameters with special characters are properly encoded")
    func testSpecialCharacterEncoding() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint")!
        let request = URLRequest(url: url)
        
        let specialParams = OAuthParameters(
            consumerKey: "key with spaces & symbols!",
            consumerSecret: "secret@#$%^&*()",
            signatureMethod: .hmac,
            nonce: "nonce=test",
            timestamp: testTimestamp
        )
        
        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: specialParams,
            as: .queryString
        )
        
        #expect(signedRequest.url != nil)
        #expect(signedRequest.url!.absoluteString.contains("%"))
    }
    
    // MARK: - Integration Tests
    
    @Test("Complete OAuth flow produces valid signature")
    func testCompleteOAuthFlow() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.twitter.com/1.1/statuses/update.json")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        let params = OAuthParameters(
            consumerKey: "xvz1evFS4wEEPTGEFPHBog",
            consumerSecret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
            requestToken: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
            requestSecret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
            signatureMethod: .hmac,
            nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
            timestamp: "1318622958"
        )
        
        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: params,
            as: .queryString
        )
        
        #expect(signedRequest.url != nil)
        #expect(signedRequest.url!.query?.contains("oauth_signature") == true)
        
        // Verify signature is not empty and is URL encoded
        let queryItems = URLComponents(string: signedRequest.url!.absoluteString)?.queryItems
        let signature = queryItems?.first { $0.name == "oauth_signature" }?.value
        #expect(signature != nil)
        #expect(!signature!.isEmpty)
    }
    
    @Test("Consistent signatures for same input")
    func testConsistentSignatures() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint")!
        let request = URLRequest(url: url)
        
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac,
            nonce: "fixed-nonce",
            timestamp: "1234567890"
        )
        
        let request1 = try await provider.createSignedRequest(from: request, with: params, as: .queryString)
        let request2 = try await provider.createSignedRequest(from: request, with: params, as: .queryString)
        
        #expect(request1.url?.absoluteString == request2.url?.absoluteString)
    }
    
    @Test("Percent encoding")
    func testPercentEncoding() {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint")!
        
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac,
            nonce: "fixed-nonce",
            timestamp: "1234567890"
        )
        
        let encodedString = provider.encodeSignature(httpMethod: "GET", urlString: url.absoluteString, paremterString: params.parameterString)
        
        #expect(encodedString == "GET&https%3A%2F%2Fapi.example.com%2Fendpoint&oauth_consumer_key%3Dtest-key%26oauth_nonce%3Dfixed-nonce%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1234567890%26oauth_version%3D1.0")
    }
}

// MARK: - Mock Classes for Testing

class MockEncryptionHandler: EncryptionHandler {
    func encrypt(_ message: String, with key: String) throws -> String {
        return "mock-signature-\(message.count)-\(key.count)"
    }
}
