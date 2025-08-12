//
//  AuthenticationProvider.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

/// A protocol for OAuth authentication providers.
///
/// Types conforming to this protocol can create digitally signed
/// HTTP requests using OAuth 1.0 authentication. This abstraction
/// allows for different OAuth implementations while maintaining
/// a consistent interface.
///
/// ## Usage
///
/// Implement this protocol to create custom OAuth providers:
///
/// ```swift
/// class CustomOAuthProvider: AuthenticationProvider {
///     func createSignedRequest(
///         from urlRequest: URLRequest,
///         with parameters: OAuthParameters,
///         as transmissionType: ParameterTransmissionType
///     ) async throws -> URLRequest {
///         // Custom OAuth implementation
///     }
/// }
/// ```
///
/// ## Topics
///
/// ### Required Methods
/// - ``createSignedRequest(from:with:as:)``
///
/// ## See Also
/// - ``OAuthProvider``
/// - ``OAuthParameters``
/// - ``ParameterTransmissionType``
public protocol AuthenticationProvider {
    /// Creates a digitally signed OAuth request.
    ///
    /// Implementations should generate an OAuth signature for the provided
    /// request and include the signature along with OAuth parameters
    /// according to the specified transmission method.
    ///
    /// - Parameters:
    ///   - urlRequest: The original unsigned HTTP request
    ///   - parameters: OAuth parameters including credentials and signature configuration
    ///   - transmissionType: Method for including OAuth parameters in the request
    ///
    /// - Returns: A new signed `URLRequest` with OAuth parameters and signature
    ///
    /// - Throws: Implementation-specific errors for signature generation or request construction failures
    func createSignedRequest(from urlRequest: URLRequest,
                             with parameters: OAuthParameters,
                             as transmissionType: ParameterTransmissionType
    ) async throws -> URLRequest
}
