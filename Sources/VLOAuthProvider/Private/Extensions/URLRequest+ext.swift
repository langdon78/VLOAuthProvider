//
//  URLComponents+ext.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation
import Collections

extension URLRequest {
    func addingAuthorizationHeader(from parametersMap: OrderedDictionary<String, String>) -> URLRequest {
        let authorizationHeaderPrefix: String = "OAuth "
        let authorizationHeaderKey: String = "Authorization"

        let flattenedParams = parametersMap.reduce(into: authorizationHeaderPrefix) { result, item in
            result.append("\(item.key)=\"\(item.value)\"")
            if let lastItem = parametersMap.reversed().first,
               item != lastItem {
                result.append(",")
            }
        }
        var updatedRequest = self
        updatedRequest.addValue(flattenedParams, forHTTPHeaderField: authorizationHeaderKey)
        return updatedRequest
    }
}
