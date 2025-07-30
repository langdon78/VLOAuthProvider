//
//  HMACEncryptionHandler.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation
import CommonCrypto

/// Handles cryptographic hashing
/// using supported methods from
/// CommonCrypto library (i.e. MD5, SHA1 etc.)
public class HMACEncryptionHandler: EncryptionHandler {
    let hashAlgorithmType: HashAlgorithmType
    
    init(hashAlgorithmType: HashAlgorithmType = .sha1) {
        self.hashAlgorithmType = hashAlgorithmType
    }
    
    /// Function to calculate a hash-based message authentication code (HMAC)
    ///
    /// - Parameters:
    ///   - message: the message to be encrypted
    ///   - using: hash function used (one of: .sha1, .md5, .sha224, .sha256, .sha384, .sha512, .sha224)
    ///   - with: the key or secret
    /// - Returns: the HMAC encrypted string or EncryptionError
    public func encrypt(
        _ message:  String,
        with key:   String
    ) throws -> String  {
        
        // Exit early if parameters malformed or type is plaintext
        guard !message.isEmpty else { throw EncryptionError.emptyMessage }
        guard !key.isEmpty else { throw EncryptionError.emptyKey }
        
        // If algorithm is present, apply encryption
        guard let hashAlgorithm = hashAlgorithmType.algorithm else {
            throw EncryptionError.unexpectedHashType
        }
        
        // Convert key and message to .utf8
        guard let encodedKey = key.data(using: .utf8) else { throw EncryptionError.encodingError }
        guard let encodedMessage = message.data(using: .utf8) else { throw EncryptionError.encodingError }
        
        // CommonCrypto hash function accepts a pointer to key and message bytes
        return encodedMessage.withUnsafeBytes { messagePtr in
            encodedKey.withUnsafeBytes { keyPtr in
                // C-style function call
                var result = hashAlgorithm.allocated
                CCHmac(hashAlgorithm.ccIdentifier,
                       keyPtr.baseAddress,
                       keyPtr.count,
                       messagePtr.baseAddress,
                       messagePtr.count,
                       &result)
                return Data(result).base64EncodedString()
            }
        }
    }
    
}
