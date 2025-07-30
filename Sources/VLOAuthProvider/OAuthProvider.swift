//
//  OAuthProvider.swift
//
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

/// Handles oAuth1.0 authentication
/// specified by RFC 5849.
/// https://tools.ietf.org/html/rfc5849#section-3.4.2

public class OAuthProvider: AuthenticationProvider {
    private func rfc3986Encode(_ str: String) -> String {
        // https://tools.ietf.org/html/rfc5849#section-3.6
        let unreservedRFC3986 = CharacterSet(charactersIn: "-._~?")
        let allowed = CharacterSet.alphanumerics.union(unreservedRFC3986)
        return str.addingPercentEncoding(withAllowedCharacters: allowed) ?? str
    }
    
    func encodeSignature(httpMethod: String, urlString: String, paremterString: String) -> String {
        return "\(httpMethod)&\(rfc3986Encode(urlString))&\(rfc3986Encode(paremterString))"
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
    
    func createRequestWithQueryParams(request: URLRequest, with parameters: OAuthParameters) async throws -> URLRequest {
        guard let url = request.url,
              let httpMethod = request.httpMethod
        else { return request }
        
        let signature = try await makeSignature(
            httpMethod: httpMethod,
            urlString: url.absoluteString,
            parameters: parameters
        )
        let encodedSignature = rfc3986Encode(signature)
        let signedUrl = url.appending(queryItems: parameters.buildQuery(with: encodedSignature))
        return URLRequest(url: signedUrl, cachePolicy: request.cachePolicy, timeoutInterval: request.timeoutInterval)
    }
    
    func createRequestWithAuthorizationHeader(request: URLRequest, with parameters: OAuthParameters) async throws -> URLRequest {
        guard let url = request.url,
              let httpMethod = request.httpMethod
        else { return request }
        
        let signature = try await makeSignature(
            httpMethod: httpMethod,
            urlString: url.absoluteString,
            parameters: parameters
        )
        
        return parameters.add(signature: signature, to: request)
    }
    
    public func createSignedRequest(
        from urlRequest: URLRequest,
        with parameters: OAuthParameters,
        as transmissionType: ParameterTransmissionType
    ) async throws -> URLRequest {
        switch transmissionType {
            case .header:
            return try await createRequestWithAuthorizationHeader(request: urlRequest, with: parameters)
        case .queryString:
            return try await createRequestWithQueryParams(request: urlRequest, with: parameters)
        case .formData:
            fatalError("Form data transmission is not yet supported")
        }
    }
}
