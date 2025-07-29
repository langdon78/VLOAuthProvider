//
//  EncryptionHandler.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

public protocol EncryptionHandler {
    static func encrypt(_ message:  String, using hash: HashAlgorithmType, with key: String) throws -> String
}

extension EncryptionHandler where Self == HMACEncryptionHandler {
    static func encrypt(_ message:  String, with key: String) throws -> String {
        return try HMACEncryptionHandler.encrypt(message, using: .sha1, with: key)
    }
}

extension EncryptionHandler where Self == RSAEncryptionHandler {
    static func encrypt(_ message:  String, with key: String) throws -> String {
        return try RSAEncryptionHandler.encrypt(message, using: .sha1, with: key)
    }
}
