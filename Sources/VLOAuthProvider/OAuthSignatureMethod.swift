//
//  OAuthSignatureMethod.swift
//  
//
//  Created by James Langdon on 11/6/22.
//

import Foundation

public enum OAuthSignatureMethod: String {
    case hmacSha1 = "HMAC-SHA1"
    case plaintext = "PLAINTEXT"
    case rsaSha1 = "RSA-SHA1"
}

extension OAuthSignatureMethod: CustomStringConvertible {
    public var description: String {
        return rawValue
    }
}

extension OAuthSignatureMethod {
    internal var hashAlgorithmType: HashAlgorithmType {
        switch self {
        case .plaintext: return .plaintext
        case .hmacSha1: return .sha1
        case .rsaSha1: return .rsaSha1
        }
    }
}
