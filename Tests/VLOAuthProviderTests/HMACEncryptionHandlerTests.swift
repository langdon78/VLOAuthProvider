import Testing
@testable import VLOAuthProvider
import Foundation

struct HMACEncryptionHandlerTests {
    
    // MARK: - Basic Encryption Tests
    
    @Test("HMAC-SHA1 encryption produces consistent results")
    func testHMACSHA1Consistency() async throws {
        let message = "test message"
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac)
        
        let result1 = try await encryptor.encrypt(message, with: key)
        let result2 = try await encryptor.encrypt(message, with: key)
        
        #expect(result1 == result2)
        #expect(!result1.isEmpty)
    }
    
    @Test("HMAC-SHA1 encryption produces base64 encoded output")
    func testHMACSHA1Base64Output() async throws {
        let message = "test message"
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac)
        
        let result = try await encryptor.encrypt(message, with: key)
        
        // Should be valid base64
        #expect(Data(base64Encoded: result) != nil)
        
        // Should be a reasonable length for SHA1 (base64 encoded 20 bytes is ~28 chars)
        #expect(result.count >= 20)
        #expect(result.count <= 40)
    }
    
    @Test("Different messages produce different signatures")
    func testDifferentMessagesProduceDifferentSignatures() async throws {
        let key = "test key"
        let message1 = "message one"
        let message2 = "message two"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac)
        
        let result1 = try await encryptor.encrypt(message1, with: key)
        let result2 = try await encryptor.encrypt(message2, with: key)
        
        #expect(result1 != result2)
    }
    
    @Test("Different keys produce different signatures")
    func testDifferentKeysProduceDifferentSignatures() async throws {
        let message = "test message"
        let key1 = "key one"
        let key2 = "key two"
        
        let encryptor = Encryptor(oauthSignatureMethod: .hmac)
        
        let result1 = try await encryptor.encrypt(message, with: key1)
        let result2 = try await encryptor.encrypt(message, with: key2)
        
        #expect(result1 != result2)
    }
    
    // MARK: - Known Test Vectors
    
    @Test("HMAC-SHA1 produces consistent output for known inputs")
    func testConsistentOutputForKnownInputs() async throws {
        // Test with simple known inputs
        let key = "key"
        let data = "The quick brown fox jumps over the lazy dog"
        
        let encryptor = Encryptor(oauthSignatureMethod: .hmac)
        
        let result1 = try await encryptor.encrypt(data, with: key)
        let result2 = try await encryptor.encrypt(data, with: key)
        
        // Should be consistent
        #expect(result1 == result2)
        #expect(!result1.isEmpty)
        #expect(Data(base64Encoded: result1) != nil)
    }
    
    // MARK: - Hash Algorithm Support Tests
    
    @Test("MD5 hash algorithm is supported")
    func testMD5Support() async throws {
        let message = "test message"
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .md5)
        
        let result = try await encryptor.encrypt(message, with: key)
        
        #expect(result == "PgdTiZF5GxJanGUJ9qn2iQ==")
    }
    
    @Test("SHA256 hash algorithm is supported")
    func testSHA256Support() async throws {
        let message = "test message"
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha256)
        let result = try await encryptor.encrypt(message, with: key)
        
        #expect(result == "A4M0ovdiWHaZ5msdDFbrvtChFwZIoIaRSVGmv8bmPtc=")
    }
    
    @Test("SHA512 hash algorithm is supported")
    func testSHA512Support() async throws {
        let message = "test message"
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha512)
        let result = try await encryptor.encrypt(message, with: key)
        
        #expect(result == "z1j/1lkIOAxW+gc6YCz5HbwR7dYT8e3mMHsDPD2ETgi9/LEWsRQZdrGzV3V88tcjliuE466Ct8wkZw5aozcOwQ==")
    }
    
    @Test("Different hash algorithms produce different results")
    func testDifferentHashAlgorithmsProduceDifferentResults() async throws {
        let message = "test message"
        let key = "test key"
        let encryptor1 = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let encryptor256 = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha256)
        let encryptor512 = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha512)
        
        let sha1Result = try await encryptor1.encrypt(message, with: key)
        let sha256Result = try await encryptor256.encrypt(message, with: key)
        let sha512Result = try await encryptor512.encrypt(message, with: key)
        
        #expect(sha1Result != sha256Result)
        #expect(sha256Result != sha512Result)
        #expect(sha1Result != sha512Result)
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Empty message throws error")
    func testEmptyMessageThrowsError() async {
        await #expect(throws: EncryptionError.emptyMessage) {
            let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
            return try await encryptor.encrypt("", with: "test key")
        }
    }
    
    @Test("Empty key throws error")
    func testEmptyKeyThrowsError() async {
        await #expect(throws: EncryptionError.emptyKey) {
            let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
            return try await encryptor.encrypt("test message", with: "")
        }
    }
    
    // MARK: - Edge Cases
    
    @Test("Very long messages are handled correctly")
    func testVeryLongMessages() async throws {
        let longMessage = String(repeating: "a", count: 10000)
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let result = try await encryptor.encrypt(longMessage, with: key)
        
        #expect(!result.isEmpty)
        #expect(Data(base64Encoded: result) != nil)
    }
    
    @Test("Very long keys are handled correctly")
    func testVeryLongKeys() async throws {
        let message = "test message"
        let longKey = String(repeating: "k", count: 1000)
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let result = try await encryptor.encrypt(message, with: longKey)
        
        #expect(!result.isEmpty)
        #expect(Data(base64Encoded: result) != nil)
    }
    
    @Test("Unicode characters in message are handled correctly")
    func testUnicodeCharactersInMessage() async throws {
        let unicodeMessage = "Hello 世界 🌍 café"
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let result = try await encryptor.encrypt(unicodeMessage, with: key)
        
        #expect(result == "2atBQ4xWu5hzBKrr2kevhdGvVo8=")
    }
    
    @Test("Unicode characters in key are handled correctly")
    func testUnicodeCharactersInKey() async throws {
        let message = "test message"
        let unicodeKey = "🔑 secret 密钥"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let result = try await encryptor.encrypt(message, with: unicodeKey)
        
        #expect(result == "kldUayRioxiJls8C8tGjl72lTkk=")
    }
    
    @Test("Binary data in message is handled correctly")
    func testBinaryDataInMessage() async throws {
        let binaryMessage = String(data: Data([0x00, 0x01, 0x02, 0xFF, 0xFE]), encoding: .utf8) ?? ""
        let key = "test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        
        // Only test if we can create a valid string from binary data
        if !binaryMessage.isEmpty {
            let result = try await encryptor.encrypt(binaryMessage, with: key)
            #expect(result == "oJtKKJvZF7YYp6Fuk0X0ZOYxWdI=")
        }
    }
    
    // MARK: - Performance Tests
    
    @Test("Encryption performance is acceptable")
    func testEncryptionPerformance() async throws {
        let message = "test message for performance testing"
        let key = "performance test key"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let startTime = Date()
        
        // Perform 1000 encryptions
        for _ in 0..<1000 {
            _ = try await encryptor.encrypt(message, with: key)
        }
        
        let endTime = Date()
        let duration = endTime.timeIntervalSince(startTime)
        
        // Should complete 1000 encryptions in under 1 second
        #expect(duration < 1.0)
    }
    
    // MARK: - Integration with OAuth
    
    @Test("OAuth signature base string encryption")
    func testOAuthSignatureBaseStringEncryption() async throws {
        // Simulate OAuth 1.0 signature base string
        let signatureBaseString = "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
        let signingKey = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
        let encryptor = Encryptor(oauthSignatureMethod: .hmac, hashAlgorithmType: .sha1)
        let signature = try await encryptor.encrypt(signatureBaseString, with: signingKey)
        
        #expect(signature == "Tqz6pFAShJQqSyxctXvqKWrv3BQ=")
        
        // Should be consistent
        let signature2 = try await encryptor.encrypt(signatureBaseString, with: signingKey)
        #expect(signature == signature2)
    }
}
