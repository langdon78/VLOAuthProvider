//
//  OAuthProvider.swift
//
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

/// A complete OAuth 1.0 authentication provider implementation.
///
/// `OAuthProvider` handles the complex process of creating digitally signed
/// HTTP requests according to the OAuth 1.0 specification (RFC 5849).
/// It supports all three signature methods and multiple parameter transmission options.
///
/// ## Overview
///
/// OAuth 1.0 requires cryptographic signatures on all requests to verify
/// the identity of the client application. This provider handles:
/// - Signature base string construction
/// - Parameter normalization and encoding  
/// - Digital signature generation
/// - Request modification for different transmission methods
///
/// ## Supported Signature Methods
///
/// - **HMAC-SHA1**: Most commonly used, based on shared secrets
/// - **PLAINTEXT**: Simple but requires HTTPS
/// - **RSA-SHA1**: Uses public key cryptography
///
/// ## Parameter Transmission
///
/// OAuth parameters can be included in requests via:
/// - **Query String**: Parameters appended to URL
/// - **Authorization Header**: Parameters in HTTP Authorization header
/// - **Form Data**: Parameters in request body (not yet implemented)
///
/// ## Usage
///
/// Basic usage with query string parameters:
///
/// ```swift
/// let provider = OAuthProvider()
/// let parameters = OAuthParameters(
///     consumerKey: "your-key",
///     consumerSecret: "your-secret", 
///     signatureMethod: .hmac
/// )
///
/// let signedRequest = try await provider.createSignedRequest(
///     from: originalRequest,
///     with: parameters,
///     as: .queryString
/// )
/// ```
///
/// Using authorization header (recommended):
///
/// ```swift  
/// let signedRequest = try await provider.createSignedRequest(
///     from: originalRequest,
///     with: parameters,
///     as: .header
/// )
/// ```
///
/// ## Topics
///
/// ### Creating Signed Requests
/// - ``createSignedRequest(from:with:as:)``
///
/// ### Initialization
/// - ``init()``
///
/// ## See Also
/// - ``AuthenticationProvider``
/// - ``OAuthParameters``
/// - ``ParameterTransmissionType``
public class OAuthProvider: AuthenticationProvider {
    private let percentEncoder: PercentEncoderProtocol = PercentEncoder()
    
    /// Creates a new OAuth provider instance.
    public init() {}

    /// Creates a digitally signed OAuth request.
    ///
    /// This method takes an unsigned HTTP request and OAuth parameters,
    /// then generates a cryptographic signature and modifies the request
    /// to include the signature and OAuth parameters.
    ///
    /// ## Process
    ///
    /// 1. Constructs the OAuth signature base string from the request
    /// 2. Generates a digital signature using the specified signature method
    /// 3. Adds OAuth parameters and signature to the request using the specified transmission method
    ///
    /// ## Error Handling
    ///
    /// Throws errors in the following cases:
    /// - Invalid or missing URL in the request
    /// - Missing HTTP method
    /// - Cryptographic signature generation failures
    /// - Invalid OAuth parameters
    ///
    /// - Parameters:
    ///   - request: The original unsigned HTTP request
    ///   - parameters: OAuth parameters including credentials and configuration
    ///   - transmissionType: How to include OAuth parameters in the request (`.header` recommended)
    ///
    /// - Returns: A new `URLRequest` with OAuth signature and parameters added
    ///
    /// - Throws: `URLError.badURL` for malformed URLs, `EncryptionError` for signature failures
    public func createSignedRequest(
        from request: URLRequest,
        with parameters: OAuthParameters,
        as transmissionType: ParameterTransmissionType
    ) async throws -> URLRequest {
        guard let url = request.url,
              let httpMethod = request.httpMethod
        else { throw URLError(.badURL) }
        
        let signature = try await makeSignature(
            httpMethod: httpMethod,
            urlString: url.absoluteString,
            parameters: parameters
        )
        
        switch transmissionType {
            case .header:
            return try await createRequestWithAuthorizationHeader(
                request: request,
                signature: signature,
                with: parameters
            )
        case .queryString:
            return try await createRequestWithQueryParams(
                request: request,
                signature: signature,
                with: parameters
            )
        case .formData:
            fatalError("Form data transmission is not yet supported")
        }
    }
}


extension OAuthProvider {
    
    func createRequestWithQueryParams(
        request: URLRequest,
        signature: String,
        with parameters: OAuthParameters
    ) async throws -> URLRequest {
        var signedRequest = request
        let encodedSignature = percentEncoder.encode(signature)
        let parametersWithSignature = parameters.add(signature: encodedSignature)
        let queryItems = parametersWithSignature.map { URLQueryItem(name: $0.key.rawValue, value: $0.value) }
        signedRequest.url = request.url?.appending(queryItems: queryItems)
        return signedRequest
    }
    
    func createRequestWithAuthorizationHeader(
        request: URLRequest,
        signature: String,
        with parameters: OAuthParameters
    ) async throws -> URLRequest {
        let parametersWithSignature = parameters.add(signature: signature)
        let serializedParameters = OAuthParameterHelper.serialize(parametersMap: parametersWithSignature)
        return request.addingAuthorizationHeader(from: serializedParameters)
    }
    
    func encodeSignature(httpMethod: String, urlString: String, paremterString: String) -> String {
        let encodedUrlString = percentEncoder.encode(urlString)
        let encodedParameters = percentEncoder.encode(paremterString)
        return "\(httpMethod)&\(encodedUrlString)&\(encodedParameters)"
    }
    
    func makeSignature(
        httpMethod: String,
        urlString: String,
        parameters: OAuthParameters
    ) async throws -> String {
        let encodedSignature = encodeSignature(
            httpMethod: httpMethod,
            urlString: urlString,
            paremterString: parameters.parameterString
        )
        let hmacSignatureKey = "\(parameters.consumerSecret)&\(parameters.requestSecret ?? "")"
        let signatureKey = parameters.rsaPrivateKey ?? hmacSignatureKey
        let encryptor = Encryptor(oauthSignatureMethod: parameters.signatureMethod)
        return try await encryptor.encrypt(encodedSignature, with: signatureKey)
    }
    
}
