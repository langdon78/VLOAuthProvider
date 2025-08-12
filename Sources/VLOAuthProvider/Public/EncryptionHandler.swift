//
//  EncryptionHandler.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

/// A protocol for implementing OAuth signature encryption methods.
///
/// Types conforming to this protocol provide cryptographic functionality
/// for generating OAuth signatures. Different implementations handle
/// different signature methods (HMAC-SHA1, PLAINTEXT, RSA-SHA1).
///
/// ## Custom Implementation
///
/// Implement this protocol to support additional signature methods:
///
/// ```swift
/// struct CustomEncryptionHandler: EncryptionHandler {
///     func encrypt(_ message: String, with key: String) throws -> String {
///         // Custom cryptographic implementation
///         return generatedSignature
///     }
/// }
/// ```
///
/// ## Topics
///
/// ### Required Methods
/// - ``encrypt(_:with:)``
///
/// ## See Also
/// - ``OAuthSignatureMethod``
/// - ``EncryptionError``
public protocol EncryptionHandler {
    /// Encrypts a message using the provided key.
    ///
    /// This method generates a cryptographic signature for the OAuth
    /// signature base string using the appropriate algorithm for the
    /// signature method.
    ///
    /// - Parameters:
    ///   - message: The OAuth signature base string to be signed
    ///   - key: The signing key (format depends on signature method)
    ///
    /// - Returns: Base64-encoded signature string
    ///
    /// - Throws: ``EncryptionError`` for cryptographic failures or invalid inputs
    func encrypt(_ message:  String, with key: String) throws -> String
}
