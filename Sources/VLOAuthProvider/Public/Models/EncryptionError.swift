//
//  EncryptionError.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 7/27/25.
//

import Foundation

public enum EncryptionError: Error {
    case emptyMessage
    case emptyKey
    case unexpectedHashType
    case invalidPrivateKey
    case encodingError
    case signingFailed
}
