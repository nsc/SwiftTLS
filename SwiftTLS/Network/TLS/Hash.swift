//
//  Hash.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 17.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

protocol Hash {
    static func hash(_ m: [UInt8]) -> [UInt8]
    
    static var blockLength: Int { get }
    func update(_ m: [UInt8])
    func finalize() -> [UInt8]
}
