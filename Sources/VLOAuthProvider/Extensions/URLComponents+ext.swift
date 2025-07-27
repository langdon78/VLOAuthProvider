//
//  URLComponents+ext.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

internal extension URLComponents {
    var baseURLStringWithPath: String {
        guard let url = url else { return "" }
        var formattedScheme = ""
        if let scheme = url.scheme {
            formattedScheme = scheme + "://"
        }
        return "\(formattedScheme)\(url.host ?? "")\(url.path)"
    }
}
