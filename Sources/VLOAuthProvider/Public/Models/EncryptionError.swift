//
//  EncryptionError.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 7/27/25.
//

import Foundation

/// Errors that can occur during OAuth signature generation.
///
/// These errors cover various failure scenarios in the cryptographic
/// signature generation process, from input validation to cryptographic
/// operations.
///
/// ## Error Categories
///
/// - **Input Validation**: ``emptyMessage``, ``emptyKey``
/// - **Configuration**: ``unexpectedHashType``, ``invalidPrivateKey``
/// - **Processing**: ``encodingError``, ``signingFailed``
///
/// ## Topics
///
/// ### Input Validation Errors
/// - ``emptyMessage``
/// - ``emptyKey``
///
/// ### Configuration Errors  
/// - ``unexpectedHashType``
/// - ``invalidPrivateKey``
///
/// ### Processing Errors
/// - ``encodingError``
/// - ``signingFailed``
///
/// ## See Also
/// - ``EncryptionHandler``
/// - ``OAuthSignatureMethod``
public enum EncryptionError: Error {
    /// The signature base string is empty or contains only whitespace.
    ///
    /// OAuth signatures require a non-empty message to sign. This error
    /// occurs when the signature base string construction fails or
    /// produces an empty result.
    case emptyMessage
    
    /// The signing key is empty or missing.
    ///
    /// All signature methods require a signing key. For HMAC methods,
    /// this is derived from consumer and token secrets. For RSA methods,
    /// this should be a valid private key.
    case emptyKey
    
    /// An unsupported or invalid hash algorithm was specified.
    ///
    /// The encryption handler received a hash algorithm type that
    /// it doesn't support or recognize.
    case unexpectedHashType
    
    /// The RSA private key is invalid or malformed.
    ///
    /// This error occurs when using RSA-SHA1 signature method with
    /// a private key that cannot be parsed or is not in the expected
    /// format (typically PEM).
    case invalidPrivateKey
    
    /// String encoding or data conversion failed.
    ///
    /// Occurs during UTF-8 encoding of strings or Base64 encoding
    /// of binary signature data.
    case encodingError
    
    /// The cryptographic signing operation failed.
    ///
    /// This is a general error for cryptographic failures that don't
    /// fall into the other specific categories. May indicate system
    /// cryptographic library issues.
    case signingFailed
}
