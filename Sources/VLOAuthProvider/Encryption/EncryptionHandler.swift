//
//  EncryptionHandler.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

public protocol EncryptionHandler {
    static func encrypt(_ message:  String, using hash: HashAlgorithmType, with key: String) -> Result<String, EncryptionError>
}
