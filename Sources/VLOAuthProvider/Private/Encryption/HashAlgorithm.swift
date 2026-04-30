//
//  HashAlgorithm.swift
//

import Foundation

#if canImport(CommonCrypto)
import CommonCrypto

struct HashAlgorithm {
    private(set) var length: Int32
    private(set) var ccIdentifier: UInt32
    private var lengthInt: Int { Int(length) }
    var allocated: [UInt8] { [UInt8](repeating: 0, count: lengthInt) }

    init(length: Int32, ccIdentifier: Int) {
        self.length = length
        self.ccIdentifier = CCHmacAlgorithm(ccIdentifier)
    }
}
#endif
