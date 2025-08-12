//
//  OAuthSignatureMethod.swift
//  
//
//  Created by James Langdon on 11/6/22.
//

import Foundation

/// OAuth 1.0 signature methods as defined in RFC 5849.
///
/// These signature methods provide different levels of security and
/// have different implementation requirements. All methods are supported
/// by the VLOAuthProvider implementation.
///
/// ## Signature Method Comparison
///
/// | Method | Security | Requirements | Use Case |
/// |--------|----------|--------------|----------|
/// | HMAC-SHA1 | High | Shared secrets | Most common |
/// | PLAINTEXT | Low | HTTPS required | Simple debugging |
/// | RSA-SHA1 | Highest | Private key | Enterprise/PKI |
///
/// ## Topics
///
/// ### Available Methods
/// - ``hmac``
/// - ``plaintext``
/// - ``rsa``
///
/// ## See Also
/// - ``OAuthParameters``
/// - ``EncryptionHandler``
public enum OAuthSignatureMethod: String {
    /// HMAC-SHA1 signature method.
    ///
    /// The most commonly used OAuth signature method. Uses HMAC-SHA1
    /// algorithm with a composite signing key derived from the consumer
    /// secret and token secret (if available).
    ///
    /// **Security**: High - Uses cryptographic hashing
    /// **Requirements**: Consumer secret and optionally token secret
    /// **Performance**: Fast
    case hmac = "HMAC-SHA1"
    
    /// PLAINTEXT signature method.
    ///
    /// A simple signature method that concatenates the consumer secret
    /// and token secret. Provides minimal security and should only be
    /// used over HTTPS connections.
    ///
    /// **Security**: Low - No cryptographic protection
    /// **Requirements**: HTTPS transport mandatory
    /// **Performance**: Fastest
    case plaintext = "PLAINTEXT"
    
    /// RSA-SHA1 signature method.
    ///
    /// Uses RSA public key cryptography with SHA-1 hashing. Requires
    /// the consumer to have an RSA private key for signing. Provides
    /// the highest security level.
    ///
    /// **Security**: Highest - Public key cryptography
    /// **Requirements**: RSA private key
    /// **Performance**: Slowest
    case rsa = "RSA-SHA1"
}

extension OAuthSignatureMethod: CustomStringConvertible {
    /// Human-readable description of the signature method.
    ///
    /// Returns the raw OAuth parameter value (e.g., "HMAC-SHA1").
    public var description: String {
        return rawValue
    }
}
