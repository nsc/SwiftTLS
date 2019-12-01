//
//  math.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 18.11.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

// result: (quotient, remainder)
func division<T : BinaryInteger>(_ a : T, _ b : T) -> (T, T)
{
    return a.quotientAndRemainder(dividingBy: b)
}

public func modular_pow(_ base : BigInt, _ exponent : BigInt, _ mod : BigInt) -> BigInt
{
    return BarrettReduction(modulus: mod).modular_pow(base, exponent)
}

//public func modular_pow<T : BinaryInteger>(_ base : T, _ exponent : T, _ mod : T) -> T
//{
//    let numBits = exponent.bitWidth
//
//    // Check for leading zero bits to avoid a couple iterations of (r * r) % mod
//    var result = T(1)
//    var r = base % mod
//    for i in 0..<numBits
//    {
//        if (exponent.isBitSet(i)) {
//            result = (result * r) % mod
//        }
//
//        r = (r * r) % mod
//    }
//
//    return result
//}

func gcd<T : BinaryInteger>(_ x : T, _ y : T) -> T
{
    var g : T = y
    
    var x = x
    var y = y
    
    while x > 0 {
        g = x
        x = y % x
        y = g
    }
    
    return g
}

func extended_euclid<T : BinaryInteger>(z : T, a : T) -> T
{
    var i = a
    var j = z
    var y1 : T = 1
    var y2 : T = 0
    
    let zero : T = 0
    while j > zero
    {
        let (quotient, remainder) = division(i, j)
        
        let y = y2 - y1 * quotient
        
        i = j
        j = remainder
        y2 = y1
        y1 = y        
    }
    
    return y2 % a
}

//public func modular_inverse(_ x : BigInt, _ y : BigInt, mod : BigInt) -> BigInt
//{
//    return BarrettReduction(modulus: mod).modular_inverse(x, y)
//}
//
public func modular_inverse<T : BinaryInteger>(_ x : T, _ y : T, mod : T) -> T
{
    let x = x > 0 ? x : x + mod
    let y = y > 0 ? y : y + mod

    let inverse = extended_euclid(z: y, a: mod)

    var result = (inverse * x) % mod

    let zero : T = 0
    if result < zero {
        result = result + mod
    }

    return result
}

public func modular_inverse(_ x : BigInt, _ y : BigInt, mod : BigInt, context: UnsafeMutablePointer<BigIntContext>? = nil) -> BigInt
{
    let x = x > 0 ? x : x + mod
    let y = y > 0 ? y : y + mod

    let inverse = extended_euclid(z: y, a: mod)

    var result = BigInt.divide(BigInt.multiply(inverse, x, context: context), mod).1

    let zero = BigInt(0)
    if result < zero {
        result = result + mod
    }

    return result
}
