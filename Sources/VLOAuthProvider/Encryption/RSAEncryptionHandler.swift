//
//  RSAEncryptionHandler.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 7/27/25.
//

import Foundation
import Security
import CommonCrypto

public class RSAEncryptionHandler: EncryptionHandler {
    let hashAlgorithmType: HashAlgorithmType
    
    init(hashAlgorithmType: HashAlgorithmType = .sha1) {
        self.hashAlgorithmType = hashAlgorithmType
    }
    
    public func encrypt(
        _ message: String,
        with privateKeyPEM: String
    ) throws -> String {

        guard !message.isEmpty else { throw EncryptionError.emptyMessage }
        guard !privateKeyPEM.isEmpty else { throw EncryptionError.emptyKey }
        guard hashAlgorithmType == .sha1 else { throw EncryptionError.unexpectedHashType }

        // Convert PEM to SecKey
        guard let privateKey = createSecKeyFromPEM(privateKeyPEM) else {
            throw EncryptionError.invalidPrivateKey
        }

        // Create SHA1 hash of message
        guard let messageData = message.data(using: .utf8) else {
            throw EncryptionError.encodingError
        }

        let hash = sha1Hash(messageData) as CFData

        // Sign the hash with RSA private key
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA1,
            hash,
            &error
        ) as? Data else {
            throw EncryptionError.signingFailed
        }

        // Return base64 encoded signature
        return signature.base64EncodedString()
    }

    private func createSecKeyFromPEM(_ pemString: String) -> SecKey? {
        // Remove PEM headers and whitespace
        let cleanPEM = pemString
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")

        guard let keyData = Data(base64Encoded: cleanPEM) else { return nil }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]

        return SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
    }

    private func sha1Hash(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}
