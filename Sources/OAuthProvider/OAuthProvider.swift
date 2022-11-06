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
    typealias Credentials = OAuthCredentials
    typealias OAuthQueryParameterValue = String
    typealias OAuthQueryParameters = [OAuthQueryParameterKey: OAuthQueryParameterValue]
    
    enum OAuthQueryParameterKey: String, CaseIterable {
        case oauth_signature_method
        case oauth_timestamp
        case oauth_nonce
        case oauth_version
        case oauth_consumer_key
        case oauth_signature
    }
    
    var currentDateString: () -> String = {
        return String(Int(Date().timeIntervalSince1970)) }
    
    var nonceUUIDString: () -> String = {
        return UUID().uuidString
    }
    
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
    
    private func defaultOAuthQueryParameters() -> OAuthQueryParameters {
        return [
            .oauth_signature_method: "HMAC-SHA1",
            .oauth_timestamp: currentDateString(),
            .oauth_nonce: nonceUUIDString(),
            .oauth_version: "1.0"
        ]
    }
    
    func preSignatureOAuthQueryItems(key: String) -> [URLQueryItem] {
        var defaultParams = defaultOAuthQueryParameters()
        defaultParams[.oauth_consumer_key] = key
        return defaultParams.map { URLQueryItem(name: $0.key.rawValue, value: $0.value) }
    }
    
    func addOAuthParams(for urlComponents: URLComponents, credentials: Credentials) -> URLComponents {
        var urlComponents = urlComponents
        let oAuthQueryItems = preSignatureOAuthQueryItems(key: credentials.consumerKey)
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
    
    func calculateSignature(urlComponents: URLComponents, httpMethod: String, credentials: Credentials) -> String {
        let hashable = hashString(httpMethod: httpMethod, urlComponents: urlComponents)
        let result = encryptionHandler.encrypt(hashable, using: .sha1, with: credentials.rfc5849FormattedSecret)
        
        switch result {
        case .success(let hashed):
            return rfc3986Encode(hashed)
        case .failure(let error):
            fatalError(error.localizedDescription)
        }
    }
    
    func addSignature(with hashed: String, to urlComponents: URLComponents) -> URL {
        var urlComponents = urlComponents
        let signatureQueryItem = URLQueryItem(name: OAuthQueryParameterKey.oauth_signature.rawValue, value: hashed)
        urlComponents.queryItems?.append(signatureQueryItem)
        return urlComponents.url!
    }
    
    func createSignedRequest(from urlRequest: URLRequest, credentials: Credentials) -> URLRequest {
        guard let url = urlRequest.url,
            let urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let httpMethod = urlRequest.httpMethod
            else { return urlRequest }
        
        var urlComponentsWithAuthParams = addOAuthParams(for: urlComponents, credentials: credentials)
        urlComponentsWithAuthParams.queryItems = sortParameters(for: urlComponentsWithAuthParams)
        let signature = calculateSignature(urlComponents: urlComponentsWithAuthParams, httpMethod: httpMethod, credentials: credentials)
        let urlSigned = addSignature(with: signature, to: urlComponentsWithAuthParams)
        var requestSigned = URLRequest(url: urlSigned)
        requestSigned.httpMethod = httpMethod
        return requestSigned
    }
    
}
