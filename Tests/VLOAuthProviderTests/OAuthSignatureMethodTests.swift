import Testing
@testable import VLOAuthProvider
import Foundation

struct OAuthSignatureMethodTests {
    
    // MARK: - Raw Value Tests
    
    @Test("HMAC-SHA1 has correct raw value")
    func testHMACSHA1RawValue() {
        let method = OAuthSignatureMethod.hmac
        #expect(method.rawValue == "HMAC-SHA1")
    }
    
    @Test("PLAINTEXT has correct raw value")
    func testPlaintextRawValue() {
        let method = OAuthSignatureMethod.plaintext
        #expect(method.rawValue == "PLAINTEXT")
    }
    
    @Test("RSA-SHA1 has correct raw value")
    func testRSASHA1RawValue() {
        let method = OAuthSignatureMethod.rsa
        #expect(method.rawValue == "RSA-SHA1")
    }
    
    // MARK: - Initialization from Raw Value Tests
    
    @Test("Can initialize HMAC-SHA1 from raw value")
    func testInitializeHMACSHA1FromRawValue() {
        let method = OAuthSignatureMethod(rawValue: "HMAC-SHA1")
        #expect(method == .hmac)
    }
    
    @Test("Can initialize PLAINTEXT from raw value")
    func testInitializePlaintextFromRawValue() {
        let method = OAuthSignatureMethod(rawValue: "PLAINTEXT")
        #expect(method == .plaintext)
    }
    
    @Test("Can initialize RSA-SHA1 from raw value")
    func testInitializeRSASHA1FromRawValue() {
        let method = OAuthSignatureMethod(rawValue: "RSA-SHA1")
        #expect(method == .rsa)
    }
    
    @Test("Returns nil for invalid raw value")
    func testInitializeWithInvalidRawValue() {
        let method = OAuthSignatureMethod(rawValue: "INVALID-METHOD")
        #expect(method == nil)
    }
    
    @Test("Raw value matching is case sensitive")
    func testRawValueCaseSensitive() {
        let lowercaseMethod = OAuthSignatureMethod(rawValue: "hmac-sha1")
        let mixedCaseMethod = OAuthSignatureMethod(rawValue: "Hmac-Sha1")
        
        #expect(lowercaseMethod == nil)
        #expect(mixedCaseMethod == nil)
    }
    
    // MARK: - CustomStringConvertible Tests
    
    @Test("Description returns raw value for HMAC-SHA1")
    func testHMACSHA1Description() {
        let method = OAuthSignatureMethod.hmac
        #expect(method.description == "HMAC-SHA1")
    }
    
    @Test("Description returns raw value for PLAINTEXT")
    func testPlaintextDescription() {
        let method = OAuthSignatureMethod.plaintext
        #expect(method.description == "PLAINTEXT")
    }
    
    @Test("Description returns raw value for RSA-SHA1")
    func testRSASHA1Description() {
        let method = OAuthSignatureMethod.rsa
        #expect(method.description == "RSA-SHA1")
    }
    
    // MARK: - Signature Method Validation Tests
    
    @Test("All signature methods are valid OAuth 1.0 methods")
    func testValidOAuthMethods() {
        let validMethods = ["HMAC-SHA1", "PLAINTEXT", "RSA-SHA1"]
        
        #expect(validMethods.contains(OAuthSignatureMethod.hmac.rawValue))
        #expect(validMethods.contains(OAuthSignatureMethod.plaintext.rawValue))
        #expect(validMethods.contains(OAuthSignatureMethod.rsa.rawValue))
    }
    
    // MARK: - Equality Tests
    
    @Test("Same signature methods are equal")
    func testSameMethodsAreEqual() {
        let method1 = OAuthSignatureMethod.hmac
        let method2 = OAuthSignatureMethod.hmac
        
        #expect(method1 == method2)
    }
    
    @Test("Different signature methods are not equal")
    func testDifferentMethodsAreNotEqual() {
        let hmacMethod = OAuthSignatureMethod.hmac
        let plaintextMethod = OAuthSignatureMethod.plaintext
        let rsaMethod = OAuthSignatureMethod.rsa
        
        #expect(hmacMethod != plaintextMethod)
        #expect(plaintextMethod != rsaMethod)
        #expect(hmacMethod != rsaMethod)
    }
    
    // MARK: - All Cases Tests
    
    @Test("All signature methods are available")
    func testAllSignatureMethodsAvailable() {
        let allCases = OAuthSignatureMethod.allCases
        
        #expect(allCases.count == 3)
        #expect(allCases.contains(.hmac))
        #expect(allCases.contains(.plaintext))
        #expect(allCases.contains(.rsa))
    }
    
    @Test("All cases have unique raw values")
    func testAllCasesHaveUniqueRawValues() {
        let allCases = OAuthSignatureMethod.allCases
        let rawValues = allCases.map { $0.rawValue }
        let uniqueRawValues = Set(rawValues)
        
        #expect(rawValues.count == uniqueRawValues.count)
    }
    
    @Test("All cases can be created from their raw values")
    func testAllCasesCanBeCreatedFromRawValues() {
        let allCases = OAuthSignatureMethod.allCases
        
        for originalCase in allCases {
            let recreatedCase = OAuthSignatureMethod(rawValue: originalCase.rawValue)
            #expect(recreatedCase == originalCase)
        }
    }
    
    // MARK: - RFC 5849 Compliance Tests
    
    @Test("Signature method values comply with RFC 5849")
    func testRFC5849Compliance() {
        // RFC 5849 Section 3.4 specifies these exact values
        #expect(OAuthSignatureMethod.hmac.rawValue == "HMAC-SHA1")
        #expect(OAuthSignatureMethod.plaintext.rawValue == "PLAINTEXT")
        #expect(OAuthSignatureMethod.rsa.rawValue == "RSA-SHA1")
    }
    
    @Test("Required signature methods are implemented")
    func testRequiredSignatureMethodsImplemented() {
        // RFC 5849 requires these three signature methods
        let requiredMethods: Set<OAuthSignatureMethod> = [.hmac, .plaintext, .rsa]
        let implementedMethods = Set(OAuthSignatureMethod.allCases)
        
        #expect(requiredMethods.isSubset(of: implementedMethods))
    }
    
    // MARK: - Integration Tests
    
    @Test("Signature methods work with OAuthParameters")
    func testSignatureMethodsWithOAuthParameters() {
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
        
        #expect(hmacParams.signatureMethod == .hmac)
        #expect(plaintextParams.signatureMethod == .plaintext)
        #expect(rsaParams.signatureMethod == .rsa)
    }
    
    @Test("Signature methods serialize correctly in query parameters")
    func testSignatureMethodsInQueryParameters() {
        let methods: [OAuthSignatureMethod] = [.hmac, .plaintext, .rsa]
        
        for method in methods {
            let params = OAuthParameters(
                consumerKey: "key",
                consumerSecret: "secret",
                signatureMethod: method
            )
            
            let queryItems = params.queryItems
            let signatureMethodItem = queryItems.first { $0.name == "oauth_signature_method" }
            
            #expect(signatureMethodItem?.value == method.rawValue)
        }
    }
    
    // MARK: - Performance Tests
    
    @Test("Raw value access is fast")
    func testRawValuePerformance() {
        let method = OAuthSignatureMethod.hmac
        let startTime = Date()
        
        // Access raw value 10000 times
        for _ in 0..<10000 {
            _ = method.rawValue
        }
        
        let endTime = Date()
        let duration = endTime.timeIntervalSince(startTime)
        
        // Should be very fast
        #expect(duration < 0.1)
    }
    
    @Test("Description access is fast")
    func testDescriptionPerformance() {
        let method = OAuthSignatureMethod.hmac
        let startTime = Date()
        
        // Access description 10000 times
        for _ in 0..<10000 {
            _ = method.description
        }
        
        let endTime = Date()
        let duration = endTime.timeIntervalSince(startTime)
        
        // Should be very fast
        #expect(duration < 0.1)
    }
}

// MARK: - Helper Extensions

extension OAuthSignatureMethod: CaseIterable {
    public static var allCases: [OAuthSignatureMethod] {
        return [.hmac, .plaintext, .rsa]
    }
}
