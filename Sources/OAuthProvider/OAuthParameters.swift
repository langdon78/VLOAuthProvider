//
//  File.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

public struct OAuthParameters {
    public var consumerKey: String
    public var consumerSecret: String
    public var userKey: String?
    public var userSecret: String?
    public var oauthVersion: String
    public var oauthSignatureMethod: OAuthSignatureMethod
    public var oauthNonce: String
    public var oauthTimestamp: String
    public var oauthCallback: URL?
    public var oauthToken: String?
    
    public var oauthSignature: String {
        switch oauthSignatureMethod {
        case .plaintext:
            return consumerSecret + "&"
        default:
            return ""
        }
    }
    
    public var rfc5849FormattedSecret: String {
        // https://tools.ietf.org/html/rfc5849#section-3.4.4
        return "\(consumerSecret)&\(userSecret ?? "")"
    }
    
    public var userVerifier: String? {
        userSecret
    }
    
    internal var parameterMap: [OAuthQueryParameterKey: String] {
        let result: [OAuthQueryParameterKey: String?] = [
            .oauth_consumer_key: consumerKey,
            .oauth_nonce: oauthNonce,
            .oauth_timestamp: oauthTimestamp,
            .oauth_signature_method: oauthSignatureMethod.rawValue,
            .oauth_signature: oauthSignature,
            .oauth_verifier: userVerifier,
            .oauth_version: oauthVersion,
            .oauth_callback: oauthCallback?.absoluteString,
            .oauth_token: oauthToken
        ]
        return result.compactMapValues({ $0 })
    }
    
    public var queryItems: [URLQueryItem] {
        parameterMap.map { URLQueryItem(name: $0.key.rawValue, value: $0.value) }
    }
    
    public init(consumerKey: String,
                consumerSecret: String,
                userKey: String? = nil,
                userSecret: String? = nil,
                oauthVersion: String = "1.0",
                oauthSignatureMethod: OAuthSignatureMethod,
                oauthNonce: String = UUID().uuidString,
                oauthTimestamp: String = String(Int(Date().timeIntervalSince1970)),
                oauthCallback: URL? = nil,
                oauthToken: String? = nil) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.userKey = userKey
        self.userSecret = userSecret
        self.oauthVersion = oauthVersion
        self.oauthSignatureMethod = oauthSignatureMethod
        self.oauthNonce = oauthNonce
        self.oauthTimestamp = oauthTimestamp
        self.oauthCallback = oauthCallback
        self.oauthToken = oauthToken
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
