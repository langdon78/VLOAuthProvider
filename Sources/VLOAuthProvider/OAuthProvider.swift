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
    private let percentEncoder: PercentEncoderProtocol = PercentEncoder()
    
    public init() {}

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
                url: url,
                cachePolicy: request.cachePolicy,
                timeoutInterval: request.timeoutInterval,
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
        url: URL,
        cachePolicy: URLRequest.CachePolicy,
        timeoutInterval: TimeInterval,
        signature: String,
        with parameters: OAuthParameters
    ) async throws -> URLRequest {
        let encodedSignature = percentEncoder.encode(signature)
        let signedUrl = url.appending(queryItems: parameters.buildQuery(with: encodedSignature))
        return URLRequest(url: signedUrl, cachePolicy: cachePolicy, timeoutInterval: timeoutInterval)
    }
    
    func createRequestWithAuthorizationHeader(
        request: URLRequest,
        signature: String,
        with parameters: OAuthParameters
    ) async throws -> URLRequest {
        return request.addToHeader(parameters: parameters, with: signature)
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
