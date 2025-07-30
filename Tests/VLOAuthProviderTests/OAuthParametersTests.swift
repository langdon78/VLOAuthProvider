import Testing
@testable import VLOAuthProvider
import Foundation

struct OAuthParametersTests {
    
    // MARK: - Initialization Tests
    
    @Test("OAuthParameters initializes with required fields")
    func testInitializationWithRequiredFields() {
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac
        )
        
        #expect(params.consumerKey == "test-key")
        #expect(params.consumerSecret == "test-secret")
        #expect(params.signatureMethod == .hmac)
        #expect(params.version == "1.0")
        #expect(params.requestToken == nil)
        #expect(params.requestSecret == nil)
    }
    
    @Test("OAuthParameters initializes with all fields")
    func testInitializationWithAllFields() {
        let callback = URL(string: "https://example.com/callback")!
        
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            requestToken: "request-token",
            requestSecret: "request-secret",
            version: "1.0",
            signatureMethod: .hmac,
            nonce: "test-nonce",
            timestamp: "1234567890",
            callback: callback,
            verifier: "test-verifier"
        )
        
        #expect(params.consumerKey == "test-key")
        #expect(params.consumerSecret == "test-secret")
        #expect(params.requestToken == "request-token")
        #expect(params.requestSecret == "request-secret")
        #expect(params.version == "1.0")
        #expect(params.signatureMethod == .hmac)
        #expect(params.nonce == "test-nonce")
        #expect(params.timestamp == "1234567890")
        #expect(params.callback == callback)
        #expect(params.verifier == "test-verifier")
    }
    
    @Test("OAuthParameters generates automatic nonce and timestamp")
    func testAutomaticNonceAndTimestamp() {
        let params1 = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac
        )
        
        let params2 = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac
        )
        
        // Nonces should be different
        #expect(params1.nonce != params2.nonce)
        
        // Timestamps should be valid
        #expect(Double(params1.timestamp) != nil)
        #expect(Double(params2.timestamp) != nil)
        
        // Both should be UUID format
        #expect(params1.nonce.contains("-"))
        #expect(params2.nonce.contains("-"))
    }
    
    // MARK: - Parameter Map Tests
    
    @Test("Parameter map contains all required OAuth parameters")
    func testParameterMapContainsRequiredParameters() {
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac,
            nonce: "test-nonce",
            timestamp: "1234567890"
        )
        
        let paramMap = params.parameterMap
        
        #expect(paramMap[.oauth_consumer_key] == "test-key")
        #expect(paramMap[.oauth_nonce] == "test-nonce")
        #expect(paramMap[.oauth_timestamp] == "1234567890")
        #expect(paramMap[.oauth_signature_method] == "HMAC-SHA1")
        #expect(paramMap[.oauth_version] == "1.0")
    }
    
    @Test("Parameter map includes optional parameters when present")
    func testParameterMapIncludesOptionalParameters() {
        let callback = URL(string: "https://example.com/callback")!
        
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            requestToken: "request-token",
            signatureMethod: .hmac,
            callback: callback,
            verifier: "test-verifier"
        )
        
        let paramMap = params.parameterMap
        
        #expect(paramMap[.oauth_token] == "request-token")
        #expect(paramMap[.oauth_callback] == "https://example.com/callback")
        #expect(paramMap[.oauth_verifier] == "test-verifier")
    }
    
    @Test("Parameter map excludes nil optional parameters")
    func testParameterMapExcludesNilParameters() {
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac
        )
        
        let paramMap = params.parameterMap
        
        #expect(paramMap[.oauth_token] == nil)
        #expect(paramMap[.oauth_callback] == nil)
        #expect(paramMap[.oauth_verifier] == nil)
    }
    
    @Test("Parameter map is sorted alphabetically")
    func testParameterMapIsSorted() {
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            requestToken: "token",
            signatureMethod: .hmac,
            nonce: "nonce",
            timestamp: "1234567890"
        )
        
        let paramMap = params.parameterMap
        let keys = Array(paramMap.keys)
        let sortedKeys = keys.sorted { $0.rawValue < $1.rawValue }
        
        #expect(keys == sortedKeys)
    }
    
    // MARK: - Query Items Tests
    
    @Test("Query items are created from parameter map")
    func testQueryItemsCreation() {
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            signatureMethod: .hmac,
            nonce: "test-nonce",
            timestamp: "1234567890"
        )
        
        let queryItems = params.queryItems
        
        #expect(queryItems.count >= 5) // At least 5 required parameters
        
        let consumerKeyItem = queryItems.first { $0.name == "oauth_consumer_key" }
        #expect(consumerKeyItem?.value == "test-key")
        
        let nonceItem = queryItems.first { $0.name == "oauth_nonce" }
        #expect(nonceItem?.value == "test-nonce")
        
        let timestampItem = queryItems.first { $0.name == "oauth_timestamp" }
        #expect(timestampItem?.value == "1234567890")
        
        let signatureMethodItem = queryItems.first { $0.name == "oauth_signature_method" }
        #expect(signatureMethodItem?.value == "HMAC-SHA1")
        
        let versionItem = queryItems.first { $0.name == "oauth_version" }
        #expect(versionItem?.value == "1.0")
    }
    
    @Test("Query items maintain alphabetical order")
    func testQueryItemsOrder() {
        let params = OAuthParameters(
            consumerKey: "test-key",
            consumerSecret: "test-secret",
            requestToken: "token",
            signatureMethod: .hmac,
            nonce: "nonce",
            timestamp: "1234567890"
        )
        
        let queryItems = params.queryItems
        let names = queryItems.map { $0.name }
        let sortedNames = names.sorted()
        
        #expect(names == sortedNames)
    }
    
    // MARK: - Signature Method Tests
    
    @Test("Different signature methods are properly set")
    func testDifferentSignatureMethods() {
        let hmacParams = OAuthParameters(
            consumerKey: "key",
            consumerSecret: "secret",
            signatureMethod: .hmac
        )
        
        let plaintextParams = OAuthParameters(
            consumerKey: "key",
            consumerSecret: "secret",
            signatureMethod: .plaintext
        )
        
        let rsaParams = OAuthParameters(
            consumerKey: "key",
            consumerSecret: "secret",
            signatureMethod: .rsa
        )
        
        #expect(hmacParams.parameterMap[.oauth_signature_method] == "HMAC-SHA1")
        #expect(plaintextParams.parameterMap[.oauth_signature_method] == "PLAINTEXT")
        #expect(rsaParams.parameterMap[.oauth_signature_method] == "RSA-SHA1")
    }
    
    // MARK: - URL Callback Tests
    
    @Test("URL callback is properly formatted in parameter map")
    func testURLCallbackFormatting() {
        let simpleURL = URL(string: "https://example.com/callback")!
        let complexURL = URL(string: "https://example.com/callback?param=value&other=test")!
        
        let simpleParams = OAuthParameters(
            consumerKey: "key",
            consumerSecret: "secret",
            signatureMethod: .hmac,
            callback: simpleURL
        )
        
        let complexParams = OAuthParameters(
            consumerKey: "key",
            consumerSecret: "secret",
            signatureMethod: .hmac,
            callback: complexURL
        )
        
        #expect(simpleParams.parameterMap[.oauth_callback] == "https://example.com/callback")
        #expect(complexParams.parameterMap[.oauth_callback] == "https://example.com/callback?param=value&other=test")
    }
    
    // MARK: - Edge Cases
    
    @Test("Empty strings are handled properly")
    func testEmptyStringHandling() {
        let params = OAuthParameters(
            consumerKey: "",
            consumerSecret: "",
            requestToken: "",
            requestSecret: "",
            signatureMethod: .hmac,
            nonce: "",
            timestamp: ""
        )
        
        let paramMap = params.parameterMap
        
        #expect(paramMap[.oauth_consumer_key] == "")
        #expect(paramMap[.oauth_token] == "")
        #expect(paramMap[.oauth_nonce] == "")
        #expect(paramMap[.oauth_timestamp] == "")
    }
    
    @Test("Special characters in parameters are preserved")
    func testSpecialCharacterPreservation() {
        let params = OAuthParameters(
            consumerKey: "key with spaces & symbols!",
            consumerSecret: "secret@#$%^&*()",
            requestToken: "token=with+equals",
            signatureMethod: .hmac,
            nonce: "nonce&with&ampersands",
            timestamp: "1234567890"
        )
        
        let paramMap = params.parameterMap
        
        #expect(paramMap[.oauth_consumer_key] == "key with spaces & symbols!")
        #expect(paramMap[.oauth_token] == "token=with+equals")
        #expect(paramMap[.oauth_nonce] == "nonce&with&ampersands")
    }
    
    // MARK: - RSA Private Key Tests
    
    @Test("RSA private key is stored correctly")
    func testRSAPrivateKeyStorage() {
        let privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC..."
        
        var params = OAuthParameters(
            consumerKey: "key",
            consumerSecret: "secret",
            signatureMethod: .rsa
        )
        params.rsaPrivateKey = privateKey
        
        #expect(params.rsaPrivateKey == privateKey)
    }
}

// MARK: - Test Extensions

extension OAuthParameters {
    static func testFixture(
        consumerKey: String = "test-consumer-key",
        consumerSecret: String = "test-consumer-secret",
        signatureMethod: OAuthSignatureMethod = .hmac,
        nonce: String = "test-nonce",
        timestamp: String = "1234567890"
    ) -> OAuthParameters {
        return OAuthParameters(
            consumerKey: consumerKey,
            consumerSecret: consumerSecret,
            signatureMethod: signatureMethod,
            nonce: nonce,
            timestamp: timestamp
        )
    }
}
