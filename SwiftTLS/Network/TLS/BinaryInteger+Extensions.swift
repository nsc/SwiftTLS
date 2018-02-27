//
//  BinaryInteger+Extensions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 22.02.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

extension BinaryInteger {
    func isBitSet(_ bitNumber : Int) -> Bool
    {
        let wordSize    = MemoryLayout<Words.Element>.size * 8
        let wordNumber  = bitNumber / wordSize
        let bit         = bitNumber % wordSize
        
        guard let words = self.words as? Array<Words.Element> else {
            fatalError("isBitSet is not implemented for anything but arrays")
        }
        
        guard wordNumber < words.count else {
            return false
        }
        
        return (UInt64(words[wordNumber]) & (UInt64(1) << UInt64(bit))) != 0
    }
}
