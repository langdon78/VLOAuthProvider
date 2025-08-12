//
//  Encryptor.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 7/30/25.
//

actor Encryptor {
    let encryptionHandler: EncryptionHandler
    
    init(oauthSignatureMethod: OAuthSignatureMethod, hashAlgorithmType: HashAlgorithmType = .sha1) {
        switch oauthSignatureMethod {
        case .rsa:
            encryptionHandler = RSAEncryptionHandler(hashAlgorithmType: hashAlgorithmType)
        case .hmac:
            encryptionHandler = HMACEncryptionHandler(hashAlgorithmType: hashAlgorithmType)
        case .plaintext:
            encryptionHandler = PlaintextEncryptionHandler()
        }
    }
    
    func encrypt(_ message: String, with key: String) throws -> String {
        try encryptionHandler.encrypt(message, with: key)
    }
}
