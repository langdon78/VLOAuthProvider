//
//  HMACEncryptionHandler.swift
//

import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#else
import Crypto
#endif

class HMACEncryptionHandler: EncryptionHandler {
    let hashAlgorithmType: HashAlgorithmType

    init(hashAlgorithmType: HashAlgorithmType = .sha1) {
        self.hashAlgorithmType = hashAlgorithmType
    }

    func encrypt(_ message: String, with key: String) throws -> String {
        guard !message.isEmpty else { throw EncryptionError.emptyMessage }
        guard !key.isEmpty else { throw EncryptionError.emptyKey }
        guard let encodedKey     = key.data(using: .utf8) else { throw EncryptionError.encodingError }
        guard let encodedMessage = message.data(using: .utf8) else { throw EncryptionError.encodingError }

#if canImport(CommonCrypto)
        guard let hashAlgorithm = hashAlgorithmType.algorithm else {
            throw EncryptionError.unexpectedHashType
        }
        return encodedMessage.withUnsafeBytes { messagePtr in
            encodedKey.withUnsafeBytes { keyPtr in
                var result = hashAlgorithm.allocated
                CCHmac(hashAlgorithm.ccIdentifier,
                       keyPtr.baseAddress, keyPtr.count,
                       messagePtr.baseAddress, messagePtr.count,
                       &result)
                return Data(result).base64EncodedString()
            }
        }
#else
        let symmetricKey = SymmetricKey(data: encodedKey)
        switch hashAlgorithmType {
        case .md5:
            return Data(HMAC<Insecure.MD5>.authenticationCode(for: encodedMessage, using: symmetricKey)).base64EncodedString()
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: encodedMessage, using: symmetricKey)).base64EncodedString()
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: encodedMessage, using: symmetricKey)).base64EncodedString()
        case .sha384:
            return Data(HMAC<SHA384>.authenticationCode(for: encodedMessage, using: symmetricKey)).base64EncodedString()
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: encodedMessage, using: symmetricKey)).base64EncodedString()
        case .sha224:
            throw EncryptionError.unexpectedHashType
        }
#endif
    }
}
