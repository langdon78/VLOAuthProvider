//
//  AuthenticationProvider.swift
//  
//
//  Created by James Langdon on 11/5/22.
//

import Foundation

public protocol AuthenticationProvider {
    associatedtype Credentials
    func createSignedRequest(from urlRequest: URLRequest, credentials: Credentials) -> URLRequest
}
