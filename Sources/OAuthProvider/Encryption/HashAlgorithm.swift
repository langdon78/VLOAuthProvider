//
//  HashAlgorithm.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation
import CommonCrypto

struct HashAlgorithm {
    private(set) var length: Int32
    private(set) var ccIdentifier: UInt32
    private var lengthInt: Int {
        return Int(length)
    }
    var allocated: [UInt8] {
        return [UInt8](repeating: 0, count: lengthInt)
    }
    
    init(length: Int32, ccIdentifier: Int) {
        self.length = length
        self.ccIdentifier = CCHmacAlgorithm(ccIdentifier)
    }
}
