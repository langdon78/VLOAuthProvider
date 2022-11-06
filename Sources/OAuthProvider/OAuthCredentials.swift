//
//  File.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

public struct OAuthCredentials {
    public var consumerKey: String
    public var consumerSecret: String
    public var userKey: String? = nil
    public var userSecret: String? = nil
    public var rfc5849FormattedSecret: String {
        // https://tools.ietf.org/html/rfc5849#section-3.4.4
        return "\(consumerSecret)&\(userSecret ?? "")"
    }
}
