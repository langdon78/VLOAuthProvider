//
//  URLComponents+ext.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

extension URLRequest {
    func appendingToHeader(parameters: OAuthParameters, with signature: String) -> URLRequest {
        parameters.appendToHeader(signature: signature, to: self)
    }
}
