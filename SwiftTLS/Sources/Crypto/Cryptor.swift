//
//  Cryptor.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 19.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

protocol Cryptor {
    func update(inputBlock: MemoryBlock, outputBlock: inout MemoryBlock) -> Bool
}
