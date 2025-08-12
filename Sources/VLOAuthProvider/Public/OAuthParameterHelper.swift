//
//  OAuthParameterHelper.swift
//  VLOAuthProvider
//
//  Created by James Langdon on 8/12/25.
//

import Foundation
import Collections

public struct OAuthParameterHelper {
    public static func computeTimestamp(for date: Date = Date.now) -> String {
        String(Int(date.timeIntervalSince1970))
    }
    
    public static func computeNonce(for uuid: UUID = UUID()) -> String {
        uuid.uuidString.data(using: .utf8)?.base64EncodedString() ?? uuid.uuidString
    }
    
    public static func serialize(
        parametersMap: OrderedDictionary<OAuthParameters.OAuthQueryParameterKey, String>
    ) -> OrderedDictionary<String, String> {
        var header: OrderedDictionary<String, String> = [:]
        parametersMap.forEach { key, value in
            header[key.rawValue] = value
        }
        return header
    }
}

extension URL {
    func addingOAuthPercentEncoding() -> String {
        let encoder = PercentEncoder()
        return encoder.encode(absoluteString)
    }
}
