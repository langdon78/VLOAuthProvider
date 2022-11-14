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
    
    func addOAuthParams(for urlComponents: URLComponents, parameters: OAuthParameters) -> URLComponents {
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
    
    func hashString(httpMethod: String, urlComponents: URLComponents) -> String {
        let params = rfc3986Encode(urlComponents.percentEncodedQuery!)
        return "\(httpMethod)&\(rfc3986Encode(urlComponents.baseURLStringWithPath))&\(params)"
    }
    
    func calculateSignature(urlComponents: URLComponents, httpMethod: String, parameters: OAuthParameters) -> String {
        let hashable = hashString(httpMethod: httpMethod, urlComponents: urlComponents)
        let result = encryptionHandler.encrypt(hashable, using: parameters.oauthSignatureMethod.hashAlgorithmType, with: parameters.rfc5849FormattedSecret)
        
        switch result {
        case .success(let hashed):
            return rfc3986Encode(hashed)
        case .failure(let error):
            fatalError(error.localizedDescription)
        }
    }
    
    func addSignature(with hashed: String, to urlComponents: URLComponents) -> URL {
        var urlComponents = urlComponents
        let signatureQueryItem = URLQueryItem(name: OAuthParameters.OAuthQueryParameterKey.oauth_signature.rawValue, value: hashed)
        urlComponents.queryItems?.append(signatureQueryItem)
        return urlComponents.url!
    }
    
    public func createSignedRequest(from urlRequest: URLRequest, parameters: OAuthParameters) -> URLRequest {
        guard let url = urlRequest.url,
              let urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let httpMethod = urlRequest.httpMethod
        else { return urlRequest }
        
        var urlComponentsWithAuthParams = addOAuthParams(for: urlComponents, parameters: parameters)
        urlComponentsWithAuthParams.queryItems = sortParameters(for: urlComponentsWithAuthParams)
        let signature = calculateSignature(urlComponents: urlComponentsWithAuthParams,
                                           httpMethod: httpMethod,
                                           parameters: parameters)
        let urlSigned = addSignature(with: signature, to: urlComponentsWithAuthParams)
        var requestSigned = URLRequest(url: urlSigned)
        requestSigned.httpMethod = httpMethod
        return requestSigned
    }
    
}
