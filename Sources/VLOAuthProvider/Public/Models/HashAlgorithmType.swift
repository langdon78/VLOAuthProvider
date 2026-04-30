//
//  HashAlgorithmType.swift
//

import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

public enum HashAlgorithmType {
    case md5
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512

    #if canImport(CommonCrypto)
    var algorithm: HashAlgorithm? {
        switch self {
        case .md5:    return HashAlgorithm(length: CC_MD5_DIGEST_LENGTH,    ccIdentifier: kCCHmacAlgMD5)
        case .sha1:   return HashAlgorithm(length: CC_SHA1_DIGEST_LENGTH,   ccIdentifier: kCCHmacAlgSHA1)
        case .sha224: return HashAlgorithm(length: CC_SHA224_DIGEST_LENGTH, ccIdentifier: kCCHmacAlgSHA224)
        case .sha256: return HashAlgorithm(length: CC_SHA256_DIGEST_LENGTH, ccIdentifier: kCCHmacAlgSHA256)
        case .sha384: return HashAlgorithm(length: CC_SHA384_DIGEST_LENGTH, ccIdentifier: kCCHmacAlgSHA384)
        case .sha512: return HashAlgorithm(length: CC_SHA512_DIGEST_LENGTH, ccIdentifier: kCCHmacAlgSHA512)
        }
    }
    #endif
}
