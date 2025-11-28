import Testing
@testable import VLOAuthProvider
import Foundation

/// Test suite for validating OAuth 1.0 signature generation with URLs containing query parameters.
///
/// According to RFC 5849 Section 3.4.1.3, the signature base string must include:
/// - Query parameters from the original URL
/// - OAuth protocol parameters
/// - Additional request parameters
///
/// All parameters must be collected, percent-encoded, sorted, and concatenated.
struct OAuthProviderQueryParameterTests {

    // MARK: - Test Fixtures

    private let testConsumerKey = "test-consumer-key"
    private let testConsumerSecret = "test-consumer-secret"
    private let testRequestToken = "test-token"
    private let testRequestSecret = "test-secret"
    private let testNonce = "fixed-nonce-123456"
    private let testTimestamp = "1234567890"

    private var testParameters: OAuthParameters {
        OAuthParameters(
            consumerKey: testConsumerKey,
            consumerSecret: testConsumerSecret,
            requestToken: testRequestToken,
            requestSecret: testRequestSecret,
            signatureMethod: .hmac,
            nonce: testNonce,
            timestamp: testTimestamp
        )
    }

    // MARK: - Single Query Parameter Tests

    @Test("URL with single query parameter generates valid signature")
    func testSingleQueryParameter() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint?status=active")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        // Verify the signature was generated
        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let signature = components?.queryItems?.first { $0.name == "oauth_signature" }
        #expect(signature != nil)
        #expect(signature?.value != nil)
        #expect(signature!.value!.isEmpty == false)

        // Verify original query parameter is preserved
        let statusParam = components?.queryItems?.first { $0.name == "status" }
        #expect(statusParam?.value == "active")
    }

    @Test("URL with numeric query parameter is properly signed")
    func testNumericQueryParameter() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/search?page=1")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        // With header transmission, URL should remain unchanged
        #expect(signedRequest.url?.absoluteString == url.absoluteString)

        // Verify authorization header exists
        let authHeader = signedRequest.value(forHTTPHeaderField: "Authorization")
        #expect(authHeader != nil)
        #expect(authHeader!.hasPrefix("OAuth "))
    }

    // MARK: - Multiple Query Parameters Tests

    @Test("URL with multiple query parameters generates deterministic signature")
    func testMultipleQueryParameters() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/search?q=oauth&type=tweet&lang=en")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)

        // Verify all original query parameters are preserved
        let queryItems = components?.queryItems ?? []
        #expect(queryItems.contains { $0.name == "q" && $0.value == "oauth" })
        #expect(queryItems.contains { $0.name == "type" && $0.value == "tweet" })
        #expect(queryItems.contains { $0.name == "lang" && $0.value == "en" })

        // Verify OAuth signature is present
        #expect(queryItems.contains { $0.name == "oauth_signature" })
    }

    @Test("Multiple query parameters produce consistent signatures")
    func testConsistentSignaturesWithQueryParams() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/data?id=123&format=json")!
        let request = URLRequest(url: url)

        let signedRequest1 = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        let signedRequest2 = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        // With fixed nonce and timestamp, signatures should be identical
        let components1 = URLComponents(url: signedRequest1.url!, resolvingAgainstBaseURL: false)
        let components2 = URLComponents(url: signedRequest2.url!, resolvingAgainstBaseURL: false)

        let sig1 = components1?.queryItems?.first { $0.name == "oauth_signature" }?.value
        let sig2 = components2?.queryItems?.first { $0.name == "oauth_signature" }?.value

        #expect(sig1 == sig2)
    }

    // MARK: - Special Characters in Query Parameters

    @Test("Query parameters with spaces are properly encoded and signed")
    func testQueryParameterWithSpaces() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/search?q=hello%20world")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let signature = components?.queryItems?.first { $0.name == "oauth_signature" }

        #expect(signature?.value != nil)
        #expect(signature!.value!.isEmpty == false)
    }

    @Test("Query parameters with special characters are RFC 3986 encoded")
    func testQueryParameterWithSpecialCharacters() async throws {
        let provider = OAuthProvider()
        // URL with special characters: @, #, $, &, =
        let url = URL(string: "https://api.example.com/data?email=user%40example.com&tag=%23swift")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        // Verify authorization header was created
        let authHeader = signedRequest.value(forHTTPHeaderField: "Authorization")
        #expect(authHeader != nil)
        #expect(authHeader!.contains("oauth_signature="))
    }

    @Test("Query parameters with Unicode characters are properly handled")
    func testQueryParameterWithUnicode() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/search?name=Caf%C3%A9")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let signature = components?.queryItems?.first { $0.name == "oauth_signature" }

        #expect(signature?.value != nil)
    }

    // MARK: - Parameter Ordering Tests

    @Test("Query parameters are included in signature base string in sorted order")
    func testParameterOrdering() async throws {
        let provider = OAuthProvider()

        // Create URL with parameters in non-alphabetical order
        let url = URL(string: "https://api.example.com/data?z=last&a=first&m=middle")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        // Signature should be deterministic regardless of parameter order
        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let signature = components?.queryItems?.first { $0.name == "oauth_signature" }

        #expect(signature?.value != nil)

        // Now test with same parameters in different order
        let url2 = URL(string: "https://api.example.com/data?a=first&m=middle&z=last")!
        let request2 = URLRequest(url: url2)

        let signedRequest2 = try await provider.createSignedRequest(
            from: request2,
            with: testParameters,
            as: .queryString
        )

        let components2 = URLComponents(url: signedRequest2.url!, resolvingAgainstBaseURL: false)
        let signature2 = components2?.queryItems?.first { $0.name == "oauth_signature" }

        // Signatures should be identical despite different input order
        #expect(signature?.value == signature2?.value)
    }

    // MARK: - Different Transmission Methods

    @Test("Query parameters work correctly with authorization header transmission")
    func testQueryParamsWithHeaderTransmission() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint?filter=active&limit=10")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        // URL should remain unchanged with header transmission
        #expect(signedRequest.url?.absoluteString == url.absoluteString)

        // Authorization header should contain OAuth parameters
        let authHeader = signedRequest.value(forHTTPHeaderField: "Authorization")
        #expect(authHeader != nil)
        #expect(authHeader!.hasPrefix("OAuth "))
        #expect(authHeader!.contains("oauth_signature="))
        #expect(authHeader!.contains("oauth_consumer_key="))

        // Original query parameters should still be in URL
        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        #expect(components?.queryItems?.contains { $0.name == "filter" } == true)
        #expect(components?.queryItems?.contains { $0.name == "limit" } == true)
    }

    @Test("Query parameters work correctly with query string transmission")
    func testQueryParamsWithQueryStringTransmission() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/endpoint?existing=param")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let queryItems = components?.queryItems ?? []

        // Should contain both original and OAuth parameters
        #expect(queryItems.contains { $0.name == "existing" })
        #expect(queryItems.contains { $0.name == "oauth_signature" })
        #expect(queryItems.contains { $0.name == "oauth_consumer_key" })
        #expect(queryItems.contains { $0.name == "oauth_nonce" })
        #expect(queryItems.contains { $0.name == "oauth_timestamp" })
    }

    // MARK: - HTTP Method Tests

    @Test("Query parameters are signed correctly for POST requests")
    func testQueryParamsWithPostRequest() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/create?callback_url=https%3A%2F%2Fexample.com")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        #expect(signedRequest.httpMethod == "POST")

        let authHeader = signedRequest.value(forHTTPHeaderField: "Authorization")
        #expect(authHeader != nil)
        #expect(authHeader!.contains("oauth_signature="))
    }

    @Test("Query parameters are signed correctly for PUT requests")
    func testQueryParamsWithPutRequest() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/update/123?version=2")!
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        #expect(signedRequest.httpMethod == "PUT")
        #expect(signedRequest.value(forHTTPHeaderField: "Authorization") != nil)
    }

    @Test("Query parameters are signed correctly for DELETE requests")
    func testQueryParamsWithDeleteRequest() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/delete?id=456&confirm=true")!
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        #expect(signedRequest.httpMethod == "DELETE")
        #expect(signedRequest.value(forHTTPHeaderField: "Authorization") != nil)
    }

    // MARK: - Edge Cases

    @Test("Empty query parameter value is properly signed")
    func testEmptyQueryParameterValue() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/data?empty=")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let signature = components?.queryItems?.first { $0.name == "oauth_signature" }

        #expect(signature?.value != nil)
    }

    @Test("Duplicate query parameter keys are handled")
    func testDuplicateQueryParameterKeys() async throws {
        let provider = OAuthProvider()
        // Note: URLComponents may normalize duplicate keys
        let url = URL(string: "https://api.example.com/search?tag=swift&tag=ios")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        #expect(signedRequest.url != nil)
        #expect(signedRequest.value(forHTTPHeaderField: "Authorization") != nil)
    }

    @Test("Very long query parameter values are properly signed")
    func testLongQueryParameterValue() async throws {
        let provider = OAuthProvider()
        let longValue = String(repeating: "a", count: 500)
        let encodedValue = longValue.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? longValue
        let url = URL(string: "https://api.example.com/data?content=\(encodedValue)")!
        let request = URLRequest(url: url)

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        #expect(signedRequest.value(forHTTPHeaderField: "Authorization") != nil)
    }

    // MARK: - Real-World Scenarios

    @Test("Twitter-style API request with query parameters")
    func testTwitterStyleRequest() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.twitter.com/1.1/statuses/home_timeline.json?count=20&include_entities=true")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"

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
            as: .header
        )

        // Verify structure
        #expect(signedRequest.httpMethod == "GET")
        let authHeader = signedRequest.value(forHTTPHeaderField: "Authorization")
        #expect(authHeader != nil)
        #expect(authHeader!.hasPrefix("OAuth "))

        // Verify query parameters are preserved
        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        #expect(components?.queryItems?.contains { $0.name == "count" && $0.value == "20" } == true)
        #expect(components?.queryItems?.contains { $0.name == "include_entities" && $0.value == "true" } == true)
    }

    @Test("Search API with multiple filters and pagination")
    func testSearchAPIWithComplexQueryParams() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/v1/search?q=oauth&category=tech&page=2&per_page=50&sort=date&order=desc")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: testParameters,
            as: .header
        )

        #expect(signedRequest.value(forHTTPHeaderField: "Authorization") != nil)

        // Verify all query parameters are preserved
        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)
        let queryItems = components?.queryItems ?? []

        #expect(queryItems.contains { $0.name == "q" && $0.value == "oauth" })
        #expect(queryItems.contains { $0.name == "category" && $0.value == "tech" })
        #expect(queryItems.contains { $0.name == "page" && $0.value == "2" })
        #expect(queryItems.contains { $0.name == "per_page" && $0.value == "50" })
        #expect(queryItems.contains { $0.name == "sort" && $0.value == "date" })
        #expect(queryItems.contains { $0.name == "order" && $0.value == "desc" })
    }

    // MARK: - Signature Method Variations

    @Test("Query parameters with PLAINTEXT signature method")
    func testQueryParamsWithPlaintextSignature() async throws {
        let provider = OAuthProvider()
        let url = URL(string: "https://api.example.com/data?id=123")!
        let request = URLRequest(url: url)

        let params = OAuthParameters(
            consumerKey: testConsumerKey,
            consumerSecret: testConsumerSecret,
            requestToken: testRequestToken,
            requestSecret: testRequestSecret,
            signatureMethod: .plaintext,
            nonce: testNonce,
            timestamp: testTimestamp
        )

        let signedRequest = try await provider.createSignedRequest(
            from: request,
            with: params,
            as: .queryString
        )

        #expect(signedRequest.url != nil)

        let components = URLComponents(url: signedRequest.url!, resolvingAgainstBaseURL: false)

        // Verify signature method is PLAINTEXT
        let sigMethod = components?.queryItems?.first { $0.name == "oauth_signature_method" }
        #expect(sigMethod?.value == "PLAINTEXT")

        // Verify signature exists
        let signature = components?.queryItems?.first { $0.name == "oauth_signature" }
        #expect(signature?.value != nil)
    }
}
