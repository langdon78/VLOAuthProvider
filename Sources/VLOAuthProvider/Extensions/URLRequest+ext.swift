//
//  URLComponents+ext.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

extension URLRequest {
    func addToHeader(parameters: OAuthParameters, with signature: String) -> URLRequest {
        parameters.addToHeader(signature: signature, to: self)
    }
}
