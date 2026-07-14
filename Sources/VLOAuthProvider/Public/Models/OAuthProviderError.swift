//
//  OAuthProviderError.swift
//  VLOAuthProvider
//

import Foundation

/// Errors that can occur while `OAuthProvider` builds a signed request,
/// distinct from the cryptographic failures covered by ``EncryptionError``.
public enum OAuthProviderError: Error {
    /// The requested `ParameterTransmissionType` has no implementation yet.
    ///
    /// Currently only `.formData` is unimplemented — see
    /// ``ParameterTransmissionType`` for status per case.
    case unsupportedTransmissionType(ParameterTransmissionType)
}
