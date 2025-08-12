//
//  Encoder.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 7/30/25.
//

import Foundation

protocol PercentEncoderProtocol {
    // Percent encoder in RFC3986 format
    func encode(_ str: String) -> String
}

class PercentEncoder: PercentEncoderProtocol {
    internal init() {}
    
    func encode(_ str: String) -> String {
        // https://tools.ietf.org/html/rfc5849#section-3.6
        let unreservedRFC3986 = CharacterSet(charactersIn: "-._~?")
        let allowed = CharacterSet.alphanumerics.union(unreservedRFC3986)
        return str.addingPercentEncoding(withAllowedCharacters: allowed) ?? str
    }
}
