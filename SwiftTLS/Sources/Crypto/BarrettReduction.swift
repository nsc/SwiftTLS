//
//  BarrettReduction.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.07.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

// This is an implementation of Barrett's reduction method as described in
// the Handboook of Applied Cryptography 14.3.3
public struct BarrettReduction : ModularReduction
{
    public let modulus: BigInt
    let µ: BigInt
    public init(modulus: BigInt) {
        self.modulus = modulus
        
        let k = modulus.words.count
        let bToThe2k = BigInt(1) << (2 * BigInt.Word.bitWidth * k)
        self.µ = bToThe2k / modulus
    }
    
    public func reduce(_ x: BigInt) -> BigInt {
        var x = x
        guard x.words.count <= modulus.words.count * 2 else {
            return x % modulus
        }
        
        let xSign = x.sign
        x = x.sign ? -x : x
        
        let k = modulus.words.count
        
        let q1 = x >> (BigInt.Word.bitWidth * (k - 1))
        let q2 = q1 * µ
        let q3 = q2 >> (BigInt.Word.bitWidth * (k + 1))
        
        var r1 = x
        r1 = r1.masked(upToHighestBit: BigInt.Word.bitWidth * (k + 1))
        var r2 = q3 * modulus
        r2 = r2.masked(upToHighestBit: BigInt.Word.bitWidth * (k + 1))
        
        var r = r1 - r2
        let tmp = r + BigInt(1) << (BigInt.Word.bitWidth * (k + 1))
        if r.sign {
            r = tmp
        }
        
        while r >= modulus {
            r = r - modulus
        }
        
        if xSign {
            r = modulus - r
        }
        
        return r
    }
}
