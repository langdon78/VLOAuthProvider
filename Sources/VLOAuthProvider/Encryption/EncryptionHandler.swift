//
//  EncryptionHandler.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

public protocol EncryptionHandler {
    func encrypt(_ message:  String, with key: String) throws -> String
}
