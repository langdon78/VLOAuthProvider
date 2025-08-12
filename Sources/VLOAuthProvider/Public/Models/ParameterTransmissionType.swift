//
//  ParameterTransmissionType.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 7/28/25.
//

/// Methods for transmitting OAuth parameters in HTTP requests.
///
/// OAuth 1.0 allows parameters to be transmitted in different parts
/// of the HTTP request. Each method has different characteristics
/// and use cases.
///
/// ## Transmission Method Comparison
///
/// | Method | Location | Pros | Cons |
/// |--------|----------|------|------|
/// | Header | Authorization header | Clean URLs, secure | More complex |
/// | Query String | URL parameters | Simple, visible | URL length limits |
/// | Form Data | Request body | Large data support | Not implemented |
///
/// ## Topics
///
/// ### Available Methods
/// - ``header``
/// - ``queryString``
/// - ``formData``
///
/// ## See Also
/// - ``OAuthProvider/createSignedRequest(from:with:as:)``
/// - ``AuthenticationProvider``
public enum ParameterTransmissionType {
    /// Transmit OAuth parameters in the request body as form data.
    ///
    /// **Status**: Not yet implemented
    /// **Use case**: Large parameter sets, POST requests
    /// **Security**: Parameters not visible in URLs or logs
    case formData
    
    /// Transmit OAuth parameters as URL query string parameters.
    ///
    /// **Status**: Fully implemented  
    /// **Use case**: Simple requests, debugging, GET requests
    /// **Security**: Parameters visible in URLs and server logs
    case queryString
    
    /// Transmit OAuth parameters in the HTTP Authorization header.
    ///
    /// **Status**: Fully implemented
    /// **Use case**: Production applications, secure requests
    /// **Security**: Parameters not visible in URLs (recommended method)
    case header
}
