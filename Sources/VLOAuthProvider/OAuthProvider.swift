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
    let encryptionHandler: EncryptionHandler.Type
    
    public init(encryptionHandler: EncryptionHandler.Type = HMACEncryptionHandler.self) {
        self.encryptionHandler = encryptionHandler
    }
    
    private func rfc3986Encode(_ str: String) -> String {
        // https://tools.ietf.org/html/rfc5849#section-3.6
        let unreservedRFC3986 = CharacterSet(charactersIn: "-._~?")
        let allowed = CharacterSet.alphanumerics.union(unreservedRFC3986)
        return str.addingPercentEncoding(withAllowedCharacters: allowed) ?? str
    }
    
    func addOAuthParamsToQuery(for urlComponents: URLComponents, parameters: OAuthParameters) -> URLComponents {
        var urlComponents = urlComponents
        let oAuthQueryItems = parameters.queryItems
        if var queryItems = urlComponents.queryItems {
            queryItems.append(contentsOf: oAuthQueryItems)
            urlComponents.queryItems = queryItems
        } else {
            urlComponents.queryItems = oAuthQueryItems
        }
        return urlComponents
    }
    
    func sortParameters(for urlComponents: URLComponents) -> [URLQueryItem]? {
        //https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
        return urlComponents.queryItems?.sorted { $0.name < $1.name }
    }
    
    func buildEncodedSignature(httpMethod: String, urlComponents: URLComponents) -> String {
        let params = rfc3986Encode(urlComponents.percentEncodedQuery!)
        return "\(httpMethod)&\(rfc3986Encode(urlComponents.baseURLStringWithPath))&\(params)"
    }
    
    func makeSignature(urlComponents: URLComponents, httpMethod: String, parameters: OAuthParameters) throws -> String {
        let hashable = buildEncodedSignature(httpMethod: httpMethod, urlComponents: urlComponents)
        let signatureKey = "\(parameters.consumerSecret)&\(parameters.requestSecret ?? "")"
        switch parameters.signatureMethod {
        case .hmacSha1:
            let hashed = try HMACEncryptionHandler.encrypt(hashable, with: signatureKey)
            return rfc3986Encode(hashed)
        case .rsaSha1:
            return try RSAEncryptionHandler.encrypt(hashable, with: parameters.rsaPrivateKey ?? "")
        case .plaintext:
            return signatureKey
        }
    }
    
    func addSignature(with hashed: String, to urlComponents: URLComponents) -> URL {
        var urlComponents = urlComponents
        let signatureQueryItem = URLQueryItem(name: OAuthParameters.OAuthQueryParameterKey.oauth_signature.rawValue, value: hashed)
        urlComponents.queryItems?.append(signatureQueryItem)
        return urlComponents.url!
    }
    
    func createRequestWithQueryParams(request: URLRequest, with parameters: OAuthParameters) throws -> URLRequest {
        guard let url = request.url,
              let urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let httpMethod = request.httpMethod
        else { return request }
        
        var urlComponentsWithAuthParams = addOAuthParamsToQuery(for: urlComponents, parameters: parameters)
        urlComponentsWithAuthParams.queryItems = sortParameters(for: urlComponentsWithAuthParams)
        let signature = try makeSignature(urlComponents: urlComponentsWithAuthParams,
                                           httpMethod: httpMethod,
                                           parameters: parameters)
        let urlSigned = addSignature(with: signature, to: urlComponentsWithAuthParams)
        var signedRequest = URLRequest(url: urlSigned)
        signedRequest.httpMethod = httpMethod
        return signedRequest
    }
    
    func createRequestWithAuthorizationHeader(request: URLRequest, with parameters: OAuthParameters) throws -> URLRequest {
        var updatedRequest = request
        let flattenedParams = parameters.queryItems.reduce(into: "OAuth ") { result, item in
            result.append("\(item.name)=\(item.value ?? "")")
        }
        updatedRequest.addValue(flattenedParams, forHTTPHeaderField: "Authorization")
        return updatedRequest
    }
    
    public func createSignedRequest(
        from urlRequest: URLRequest,
        with parameters: OAuthParameters,
        as transmissionType: ParameterTransmissionType
    ) throws -> URLRequest {
        switch transmissionType {
            case .header:
            return try createRequestWithAuthorizationHeader(request: urlRequest, with: parameters)
        case .queryString:
            return try createRequestWithQueryParams(request: urlRequest, with: parameters)
        case .formData:
            fatalError("Form data transmission is not yet supported")
        }
    }
}
