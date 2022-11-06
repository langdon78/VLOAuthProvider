//
//  File.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

struct OAuthCredentials {
    var consumerKey: String
    var consumerSecret: String
    var userKey: String? = nil
    var userSecret: String? = nil
    var rfc5849FormattedSecret: String {
        // https://tools.ietf.org/html/rfc5849#section-3.4.4
        return "\(consumerSecret)&\(userSecret ?? "")"
    }
}
