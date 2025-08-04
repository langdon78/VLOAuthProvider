//
//  File.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation
import Collections

public struct OAuthParameters {
    public var consumerKey: String
    public var consumerSecret: String
    public var requestToken: String?
    public var requestSecret: String?
    public var version: String
    public var signatureMethod: OAuthSignatureMethod
    public var nonce: String
    public var timestamp: String
    public var callback: URL?
    public var verifier: String?
    public var rsaPrivateKey: String?
    
    private let authorizationHeaderPrefix: String = "OAuth "
    private let authorizationHeaderKey: String = "Authorization"
    
    internal var parameterMap: OrderedDictionary<OAuthQueryParameterKey, String> {
        var result: OrderedDictionary<OAuthQueryParameterKey, String?> = [
            .oauth_consumer_key: consumerKey,
            .oauth_nonce: nonce,
            .oauth_timestamp: timestamp,
            .oauth_signature_method: signatureMethod.rawValue,
            .oauth_verifier: verifier,
            .oauth_version: version,
            .oauth_callback: callback?.absoluteString,
            .oauth_token: requestToken
        ]
        result.sort { $0.key.rawValue < $1.key.rawValue }
        return result.compactMapValues({ $0 })
    }
    
    public var queryItems: [URLQueryItem] {
        parameterMap.map { URLQueryItem(name: $0.key.rawValue, value: $0.value) }
    }
    
    public var parameterString: String {
        parameterMap.reduce(into: "") { result, item  in
            result += "\(item.key)=\(item.value)"
            if item.key != parameterMap.keys.last! {
                result += "&"
            }
        }
    }
    
    public init(consumerKey: String,
                consumerSecret: String,
                requestToken: String? = nil,
                requestSecret: String? = nil,
                version: String = "1.0",
                signatureMethod: OAuthSignatureMethod,
                nonce: String = UUID().uuidString,
                timestamp: String = String(Int(Date().timeIntervalSince1970)),
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
    
    func buildQuery(with signature: String) -> [URLQueryItem] {
        var mutableParameterMap = parameterMap
        mutableParameterMap[.oauth_signature] = signature
        return mutableParameterMap.map { URLQueryItem(name: $0.key.rawValue, value: $0.value) }
    }
    
    func appendToHeader(signature: String, to request: URLRequest ) -> URLRequest {
        var mutableParametersMap = parameterMap
        mutableParametersMap[.oauth_signature] = signature
        let flattenedParams = mutableParametersMap.reduce(into: authorizationHeaderPrefix) { result, item in
            result.append("\(item.key)=\"\(item.value)\"")
            if let lastItem = mutableParametersMap.reversed().first,
               item != lastItem {
                result.append(",")
            }
        }
        var updatedRequest = request
        updatedRequest.addValue(flattenedParams, forHTTPHeaderField: authorizationHeaderKey)
        return updatedRequest
    }
}

internal extension OAuthParameters {
    enum OAuthQueryParameterKey: String, CaseIterable {
        case oauth_signature_method
        case oauth_timestamp
        case oauth_nonce
        case oauth_version
        case oauth_consumer_key
        case oauth_signature
        case oauth_callback
        case oauth_verifier
        case oauth_token
    }
}
