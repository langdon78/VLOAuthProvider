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
    
    /// Function to calculate a hash-based message authentication code (HMAC)
    ///
    /// - Parameters:
    ///   - message: the message to be encrypted
    ///   - using: hash function used (one of: .sha1, .md5, .sha224, .sha256, .sha384, .sha512, .sha224)
    ///   - with: the key or secret
    /// - Returns: the HMAC encrypted string or EncryptionError
    
    public static func encrypt(
        _ message:  String,
        using hash: HashAlgorithmType,
        with key:   String
    ) throws -> String  {
        
        // Exit early if parameters malformed or type is plaintext
        guard !message.isEmpty else { throw EncryptionError.emptyMessage }
        guard !key.isEmpty else { throw EncryptionError.emptyKey }
        
        // If algorithm is present, apply encryption
        guard let hashAlgorithm = hash.algorithm else {
            throw EncryptionError.unexpectedHashType
        }
        
        // C-style function call
        var result = hashAlgorithm.allocated
        CCHmac(hashAlgorithm.ccIdentifier,
               key,
               key.count,
               message,
               message.count,
               &result)
        // Replace "+" character with urlencoded value
        return Data(result).base64EncodedString()
    }
    
}
