//
//  AuthenticationProvider.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

internal protocol AuthenticationProvider {
    associatedtype Credentials
    func createSignedRequest(from urlRequest: URLRequest, credentials: Credentials) -> URLRequest
}
