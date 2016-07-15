//
//  Signing.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

protocol Signing
{
    func sign(data : [UInt8], hashAlgorithm: HashAlgorithm) -> [UInt8]
    func verify(signature : [UInt8], data : [UInt8]) -> Bool
}