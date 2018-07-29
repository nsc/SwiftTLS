//
//  Montgomery.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 26.07.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

struct Montgomery : ModularReduction
{
    let modulus: BigInt
    let k: Int
    let r: BigInt
    let rInv: BigInt
    let mDash: BigInt
    
    init(modulus: BigInt) {
        self.modulus = modulus
        self.k = modulus.words.count * MemoryLayout<BigInt.Word>.size * 8 + 1
        self.r = BigInt(1) << k
        self.rInv = SwiftTLS.modular_inverse(BigInt(1), self.r, mod: self.modulus)
        self.mDash = SwiftTLS.modular_inverse(BigInt(-1), self.modulus, mod: self.r)
    }
    
    func reduce(_ x: BigInt) -> BigInt {
        return x % modulus
    }
    
    func montgomeryReduce(_ x: BigInt) -> BigInt {
        return reduce(x * r)
    }
    
    func multiply(_ x: BigInt, _ y: BigInt) -> BigInt {
        let t = x * y
        var m = t * mDash
        m.mask(upToHighestBit: k)
        var u = t + m * modulus
        u >>= k
        
        if u >= modulus {
            return u - modulus
        }
        
        return u
    }
    
    func modular_pow(_ base: BigInt, _ exponent: BigInt, constantTime: Bool = true) -> BigInt {
//        let rSquared = reduce(r * r)
        let x = montgomeryReduce(base)
        
        let t = exponent.highestBit
        var a = reduce(r)
        for i in (0...t).reversed() {
            a = multiply(a, a)

            let bit = BigInt(exponent.bit(at: i))
            let tmp = (constantTime || !bit.isZero) ? multiply(a, x) : a

            a = bit * tmp + (BigInt(1) - bit) * a
        }
        
        a = multiply(a, 1)
        
        return a
    }
}
