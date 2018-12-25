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

//        guard let words = self.words as? Array<Words.Element> else {
//            fatalError("isBitSet is not implemented for anything but mutable buffer pointers")
//        }

        guard let words = self.words as? BigIntStorage else {
            fatalError("isBitSet is not implemented for anything but BigIntSotrage")
        }
        
        guard wordNumber < words.count else {
            return false
        }
        
        return (UInt64(words[wordNumber]) & (UInt64(1) << UInt64(bit))) != 0
    }
    
    /// Retrieve the bit at the indicated position
    ///
    /// This method can be used to construct timing independent code that depends on
    /// whether the bit is set or not without taking a branch, e.g.
    ///
    /// instead of saying:
    ///
    ///     let a = b.bit(at: position) ? resultA : resultC
    ///
    /// you can say:
    ///
    ///     let a = b.bit(at: position) * resultA + (1 - b.bit(at: position)) * resultC
    /// - Parameter position: the position of the bit to be retrieved
    /// - Returns: returns the specified bit as 0 or 1
    func bit(at position: Int) -> Int {
        let wordSize    = MemoryLayout<Words.Element>.size * 8
        let wordNumber  = position / wordSize
        let bit         = position % wordSize
        
        guard let words = self.words as? BigIntStorage else {
            fatalError("bit(at:) is not implemented for anything but BigIntSotrage")
        }
        
        guard wordNumber < words.count else {
            return 0
        }
        
        return Int((UInt64(words[wordNumber]) & (UInt64(1) << UInt64(bit))) >> UInt64(bit))
    }
    
    var highestBit: Int {
        let wordSize    = MemoryLayout<Words.Element>.size * 8

        guard let words = self.words as? BigIntStorage else {
            fatalError("highestBit is not implemented for anything but BigIntSotrage")
        }

        guard let firstWord = words.last else {
            return -1
        }
        
        return wordSize * words.count - firstWord.leadingZeroBitCount
    }
}
