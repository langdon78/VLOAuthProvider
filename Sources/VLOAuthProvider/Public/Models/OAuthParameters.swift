//
//  OAuthParameters.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 11/5/22.
//

import Foundation
import Collections

/// A structure that manages OAuth 1.0 parameters and their serialization.
///
/// `OAuthParameters` encapsulates all the parameters required for OAuth 1.0 authentication 
/// as specified in RFC 5849. It handles automatic generation of nonces and timestamps,
/// parameter normalization, and serialization for different transmission methods.
///
/// ## Usage
///
/// Create OAuth parameters for a basic request:
///
/// ```swift
/// let params = OAuthParameters(
///     consumerKey: "your-consumer-key",
///     consumerSecret: "your-consumer-secret",
///     signatureMethod: .hmac
/// )
/// ```
///
/// For requests requiring tokens:
///
/// ```swift
/// let params = OAuthParameters(
///     consumerKey: "your-consumer-key",
///     consumerSecret: "your-consumer-secret",
///     requestToken: "oauth-token",
///     requestSecret: "oauth-token-secret",
///     signatureMethod: .hmac
/// )
/// ```
///
/// ## Parameter Management
///
/// The structure automatically handles:
/// - Nonce generation (cryptographically secure random values)
/// - Timestamp generation (Unix timestamp)
/// - Parameter normalization and sorting
/// - RFC 3986 percent encoding for callback URLs
///
/// ## Topics
///
/// ### Creating Parameters
/// - ``init(consumerKey:consumerSecret:requestToken:requestSecret:version:signatureMethod:nonce:timestamp:callback:verifier:)``
///
/// ### OAuth Credentials  
/// - ``consumerKey``
/// - ``consumerSecret``
/// - ``requestToken``
/// - ``requestSecret``
///
/// ### OAuth Protocol Parameters
/// - ``version``
/// - ``signatureMethod``
/// - ``nonce``
/// - ``timestamp``
/// - ``callback``
/// - ``verifier``
///
/// ### Cryptographic Parameters
/// - ``rsaPrivateKey``
///
/// ### Parameter Serialization
/// - ``parameterMap``
/// - ``queryItems``
/// - ``parameterString``
/// - ``encodedCallback``
/// - ``signatureMethodString``
///
/// ### Supporting Types
/// - ``OAuthQueryParameterKey``
public struct OAuthParameters {
    /// The consumer key provided by the OAuth service provider.
    ///
    /// This identifies the client application making the OAuth request.
    /// It's obtained during app registration with the service provider.
    public var consumerKey: String
    
    /// The consumer secret provided by the OAuth service provider.
    ///
    /// This is used to sign requests and verify the client's identity.
    /// Keep this value secure and never expose it in client-side code.
    public var consumerSecret: String
    
    /// The request token (also called oauth_token).
    ///
    /// This temporary token is obtained during the OAuth 1.0 flow and
    /// is used for subsequent authenticated requests.
    public var requestToken: String?
    
    /// The request token secret (also called oauth_token_secret).
    ///
    /// This secret is used along with the consumer secret to sign
    /// requests when using HMAC-SHA1 signature method.
    public var requestSecret: String?
    
    /// The OAuth version being used.
    ///
    /// Defaults to "1.0" as specified in RFC 5849.
    public var version: String
    
    /// The signature method to use for request signing.
    ///
    /// Supported methods:
    /// - `.hmac`: HMAC-SHA1 (most common)
    /// - `.plaintext`: PLAINTEXT (requires HTTPS)
    /// - `.rsa`: RSA-SHA1 (requires private key)
    public var signatureMethod: OAuthSignatureMethod
    
    /// A unique random value for this request.
    ///
    /// Automatically generated using cryptographically secure random data
    /// if not provided during initialization. Helps prevent replay attacks.
    public var nonce: String
    
    /// The timestamp when this request was created.
    ///
    /// Automatically generated as Unix timestamp if not provided during
    /// initialization. Used to prevent replay attacks.
    public var timestamp: String
    
    /// The callback URL for OAuth authorization flows.
    ///
    /// This URL will be called after the user authorizes the application.
    /// Set to `nil` for out-of-band (OOB) flows.
    public var callback: URL?
    
    /// The verification code received after user authorization.
    ///
    /// Used in the final step of the OAuth 1.0 three-legged flow
    /// to exchange temporary credentials for access tokens.
    public var verifier: String?
    
    /// RSA private key for RSA-SHA1 signature method.
    ///
    /// Required when using `.rsa` signature method. Should be in PEM format.
    public var rsaPrivateKey: String?
    
    /// Internal parameter map containing all OAuth parameters.
    ///
    /// Returns an ordered dictionary with OAuth parameter keys and their values,
    /// automatically sorted alphabetically and with nil values filtered out.
    internal var parameterMap: OrderedDictionary<OAuthQueryParameterKey, String> {
        var result: OrderedDictionary<OAuthQueryParameterKey, String?> = [
            .oauth_consumer_key     :   consumerKey,
            .oauth_nonce            :   nonce,
            .oauth_timestamp        :   timestamp,
            .oauth_signature_method :   signatureMethodString,
            .oauth_verifier         :   verifier,
            .oauth_version          :   version,
            .oauth_callback         :   encodedCallback,
            .oauth_token            :   requestToken
        ]
        result.sort { $0.key.rawValue < $1.key.rawValue }
        return result.compactMapValues({ $0 })
    }
    
    /// URL query items representation of the OAuth parameters.
    ///
    /// Converts the parameter map into an array of `URLQueryItem` objects
    /// that can be used to construct URLs or form data.
    ///
    /// - Returns: Array of query items sorted alphabetically by parameter name.
    public var queryItems: [URLQueryItem] {
        parameterMap.map { URLQueryItem(name: $0.key.rawValue, value: $0.value) }
    }
    
    /// String representation of parameters formatted for OAuth signatures.
    ///
    /// Creates a properly formatted parameter string using the format
    /// `key1=value1&key2=value2&...` with parameters sorted alphabetically.
    /// This format is used in OAuth signature base string construction.
    ///
    /// - Returns: Formatted parameter string ready for signature generation.
    public var parameterString: String {
        parameterMap.reduce(into: "") { result, item  in
            result += "\(item.key)=\(item.value)"
            if let lastParameter = parameterMap.keys.last, item.key != lastParameter {
                result += "&"
            }
        }
    }
    
    /// RFC 3986 percent-encoded callback URL.
    ///
    /// Returns the callback URL with proper percent encoding as required
    /// by the OAuth 1.0 specification.
    ///
    /// - Returns: Percent-encoded callback URL string, or `nil` if no callback is set.
    public var encodedCallback: String? {
        callback?.addingOAuthPercentEncoding()
    }
    
    /// String representation of the signature method.
    ///
    /// - Returns: The raw value of the signature method (e.g., "HMAC-SHA1").
    public var signatureMethodString: String {
        signatureMethod.rawValue
    }
    
    /// Creates a new OAuth parameters instance.
    ///
    /// - Parameters:
    ///   - consumerKey: The consumer key provided by the OAuth service provider
    ///   - consumerSecret: The consumer secret provided by the OAuth service provider
    ///   - requestToken: The request token for authenticated requests (optional)
    ///   - requestSecret: The request token secret for signature generation (optional)
    ///   - version: OAuth version, defaults to "1.0"
    ///   - signatureMethod: The signature method to use for signing requests
    ///   - nonce: Unique random value, automatically generated if not provided
    ///   - timestamp: Unix timestamp, automatically generated if not provided
    ///   - callback: Callback URL for authorization flows (optional)
    ///   - verifier: Verification code from authorization step (optional)
    public init(consumerKey: String,
                consumerSecret: String,
                requestToken: String? = nil,
                requestSecret: String? = nil,
                version: String = "1.0",
                signatureMethod: OAuthSignatureMethod,
                nonce: String = OAuthParameterHelper.computeNonce(),
                timestamp: String = OAuthParameterHelper.computeTimestamp(),
                callback: URL? = nil,
                verifier: String? = nil) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.requestToken = requestToken
        self.requestSecret = requestSecret
        self.version = version
        self.signatureMethod = signatureMethod
        self.nonce = nonce
        self.timestamp = timestamp
        self.callback = callback
        self.verifier = verifier
    }
    
    /// Internal method to add signature to parameters.
    ///
    /// - Parameter signature: The generated OAuth signature
    /// - Returns: Parameter map including the signature
    func add(signature: String) -> OrderedDictionary<OAuthQueryParameterKey, String> {
        var mutableParametersMap = parameterMap
        mutableParametersMap[.oauth_signature] = signature
        return mutableParametersMap
    }
}

public extension OAuthParameters {
    /// Keys for OAuth 1.0 query parameters as defined in RFC 5849.
    ///
    /// These parameter names are used in OAuth requests and must match
    /// the exact names specified in the OAuth 1.0 specification.
    ///
    /// ## Topics
    ///
    /// ### Core Parameters
    /// - ``oauth_consumer_key``
    /// - ``oauth_signature_method``
    /// - ``oauth_timestamp``
    /// - ``oauth_nonce``
    /// - ``oauth_version``
    /// - ``oauth_signature``
    ///
    /// ### Token Parameters  
    /// - ``oauth_token``
    ///
    /// ### Authorization Parameters
    /// - ``oauth_callback``
    /// - ``oauth_verifier``
    enum OAuthQueryParameterKey: String, CaseIterable {
        /// The consumer key parameter (`oauth_consumer_key`).
        case oauth_consumer_key
        
        /// The signature method parameter (`oauth_signature_method`).
        case oauth_signature_method
        
        /// The timestamp parameter (`oauth_timestamp`).
        case oauth_timestamp
        
        /// The nonce parameter (`oauth_nonce`).
        case oauth_nonce
        
        /// The OAuth version parameter (`oauth_version`).
        case oauth_version
        
        /// The signature parameter (`oauth_signature`).
        case oauth_signature
        
        /// The callback URL parameter (`oauth_callback`).
        case oauth_callback
        
        /// The verifier parameter (`oauth_verifier`).
        case oauth_verifier
        
        /// The token parameter (`oauth_token`).
        case oauth_token
    }
}
