//
//  ClientCredentials.swift
//  
//
//  Created by James Langdon on 11/24/22.
//

import Foundation

/// Used to identify and authenticate the client making the request
///
/// # Reference
/// [RFC 5849 1.1](https://www.rfc-editor.org/rfc/rfc5849#section-1.1)
public struct ClientCredentials {
    var consumerKey: String
    var consumerSecret: String
}
