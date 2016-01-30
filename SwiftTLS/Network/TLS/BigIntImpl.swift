//
//  BigInt.swift
//  Chat
//
//  Created by Nico Schmidt on 19.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftHelper

/// BigInt represents arbitrary precision integers
///
/// They use largest primitive possible (usually UInt64)
/// and are stored in little endian order, i.e. n = parts[0] + parts[1] * 2^64 + parts[2] * 2 ^ 128 ...
struct BigIntImpl<U where U : UnsignedIntegerType> {

    typealias PrimitiveType = U
    var parts: [PrimitiveType]
    var sign : Bool

    init(_ a : Int) {
        self.init([UInt(abs(a))], negative: a < 0)
    }

    init(_ a : UInt, negative: Bool = false) {
        self.init([a], negative: negative)
    }

    init<T where T : UnsignedIntegerType>(_ a : T) {
        self.init([a])
    }

    init(count: Int)
    {
        parts = [PrimitiveType](count:count, repeatedValue: 0)
        sign = false
    }
    
    init(capacity: Int) {
        parts = [PrimitiveType]()
        parts.reserveCapacity(capacity)
        sign = false
    }
    
    init<T where T : UnsignedIntegerType>(_ bigInt : BigIntImpl<T>)
    {
        self.init(bigInt.parts, negative: bigInt.sign)
    }
    
    /// parts are given in little endian order
    init<T where T : UnsignedIntegerType>(_ parts : [T], negative: Bool = false)
    {
        let numberInPrimitiveType = sizeof(PrimitiveType)/sizeof(T)
        
        if numberInPrimitiveType == 1 {
            self.parts = parts.map({PrimitiveType($0.toUIntMax())})
            self.sign = negative
            return
        }
        
        if numberInPrimitiveType > 0 {
            
            var number = [PrimitiveType](count: parts.count / numberInPrimitiveType + ((parts.count % sizeof(PrimitiveType) == 0) ? 0 : 1), repeatedValue: 0)
            var index = 0
            var numberIndex = 0
            var n : UIntMax = 0
            var shift = UIntMax(0)
            
            for a in parts
            {
                n = n + a.toUIntMax() << shift
                shift = shift + UIntMax(sizeof(T) * 8)
                
                if (index + 1) % numberInPrimitiveType == 0
                {
                    number[numberIndex] = PrimitiveType(n)
                    index = 0
                    n = 0
                    shift = 0
                    numberIndex += 1
                }
                else {
                    index += 1
                }
            }
            
            if n != 0 {
                number[numberIndex] = PrimitiveType(n)
            }
            self.parts = number
        }
        else {
            // T is a larger type than PrimitiveType
            let n = sizeof(T)/sizeof(PrimitiveType)
            var number = [PrimitiveType]()
            
            for a in parts
            {
                let shift : UIntMax = UIntMax(8 * sizeof(PrimitiveType))
                var mask : UIntMax = (0xffffffffffffffff >> UIntMax(64 - shift))
                for i in 0 ..< n
                {
                    let part : PrimitiveType = PrimitiveType((a.toUIntMax() & mask) >> (UIntMax(i) * shift))
                    number.append(part)
                    mask = mask << shift
                }
            }
            
            while number.last != nil && number.last! == 0 {
                number.removeLast()
            }
            
            self.parts = number
        }
            
        self.sign = negative
    }
    
    init<T where T : UnsignedIntegerType>(_ parts : ArraySlice<T>, negative: Bool = false)
    {
        self.init([T](parts), negative: negative)
    }
    
    init?(hexString : String, negative : Bool = false)
    {
        var bytes = [UInt8]()
        var bytesLeft = hexString.utf8.count
        var byte : UInt8 = 0
        for c in hexString.utf8
        {
            var a : UInt8
            switch (c)
            {
            case 0x30...0x39: // '0'...'9'
                a = c - 0x30
                
            case 0x41...0x46: // 'A'...'F'
                a = c - 0x41 + 0x0a

            case 0x61...0x66: // 'a'...'f'
                a = c - 0x61 + 0x0a

            default:
                return nil
            }
            
            byte = byte << 4 + a
            
            if bytesLeft & 0x1 == 1 {
                bytes.append(byte)
            }
            
            bytesLeft -= 1
        }
        
        self.init(bytes.reverse(), negative: negative)
        self.normalize()
    }
    
    mutating func normalize()
    {
        while parts.last != nil && parts.last! == 0 {
            parts.removeLast()
        }
    }
    
    var isZero : Bool {
        get {
            return parts.count == 0 || (parts.count == 1 && parts[0] == 0)
        }
    }
    
    func isBitSet(bitNumber : Int) -> Bool
    {
        let partSize    = sizeof(PrimitiveType) * 8
        let partNumber  = bitNumber / partSize
        let bit         = bitNumber % partSize
        
        guard partNumber < self.parts.count else {
            return false
        }
        
        return (self.parts[partNumber].toUIntMax() & (UIntMax(1) << UIntMax(bit))) != 0
    }
    
//    func square() -> BigIntImpl<U>
//    {
//        let count = self.parts.count;
//        let resultCount = 2 * count
//        
//        var result = BigIntImpl<U>(count: resultCount)
//        
//        for i in 0 ..< count {
//            
//            var overflow    : Bool
//            
//            var lo      : UInt64 = 0
//            var hi      : UInt64 = 0
//            
//            let x = self.parts[i].toUIntMax()
//            NSC_multiply64(x, x, &lo, &hi)
//
//            (result.parts[2 * i], overflow) = U.addWithOverflow(result.parts[2 * i], U(lo.toUIntMax()))
//            
//            if overflow {
//                hi += 1
//            }
//
//            let c = hi
//            result.parts[2 * i] = lo
//            for j in 0 ..< (i + 1) {
//                
//                var lo      : UInt64 = 0
//                var hi      : UInt64 = 0
//                
//                NSC_multiply64(self.parts[i].toUIntMax(), self.parts[j].toUIntMax(), &lo, &hi)
//                
//                if lo == 0 && hi == 0 {
//                    continue
//                }
//                
//                if sizeof(U) < sizeof(UIntMax) {
//                    let shift : UIntMax = UIntMax(8 * sizeof(U))
//                    let mask : UIntMax = (0xffffffffffffffff >> UIntMax(64 - shift))
//                    hi = (lo & (mask << shift)) >> shift
//                    lo = lo & mask
//                }
//                
//                (result.parts[i + j], overflow) = U.addWithOverflow(result.parts[i + j], U(lo.toUIntMax()))
//                
//                if overflow {
//                    hi += 1
//                }
//                
//                var temp = hi
//                var index = i + j + 1
//                while true {
//                    (result.parts[index], overflow) = U.addWithOverflow(result.parts[index], U(temp.toUIntMax()))
//                    if overflow {
//                        temp = 1
//                        index += 1
//                    }
//                    else {
//                        break
//                    }
//                }
//            }
//        }
//        
//        result.normalize()
//        
//        result.sign = false
//        
//        return result
//
//    }
    
    static func random<U : KnowsLargerIntType>(max : BigIntImpl<U>) -> BigIntImpl<U>
    {
        let num = max.parts.count
        var n = BigIntImpl<U>(count: num)

        n.parts.withUnsafeMutableBufferPointer { arc4random_buf($0.baseAddress, num); return }
        
        n = n % max
        
        return n
    }
}

extension String {
    init<T>(stringInterpolationSegment expr : BigIntImpl<T>)
    {
        var s = expr.sign ? "-" : ""
        var onlyZeroesYet = true
        let count = Int(expr.parts.count)
        
        for i in (0..<count).reverse()
        {
            let part = expr.parts[i].toUIntMax()
            var c : UInt8
            
            var shift = (sizeof(BigIntImpl<T>.PrimitiveType.self) - 1) * 8
            var mask : UIntMax = UIntMax(0xff) << UIntMax(shift)
            for _ in 0 ..< sizeof(BigIntImpl<T>.PrimitiveType.self)
            {
                c = UInt8((part & mask) >> UIntMax(shift))
                if !onlyZeroesYet || c != 0 {
                    s += hexString(c)
                    onlyZeroesYet = false
                }
                
                mask = mask >> 8
                shift = shift - 8
            }
        }
        
        if onlyZeroesYet {
            s = "0"
        }
        
        self.init(s)
    }
}

extension BigIntImpl : CustomStringConvertible
{
    var description : String {
        return "\(self)"
    }
}

func +<U>(var a : BigIntImpl<U>, var b : BigIntImpl<U>) -> BigIntImpl<U>
{
    if a.sign != b.sign {
        if a.sign {
            return b - (-a)
        }
        else {
            return a - (-b)
        }
    }
    
    let count = max(a.parts.count, b.parts.count)
    var v = BigIntImpl<U>(capacity: count)
    v.sign = a.sign
    
    var carry : BigIntImpl<U>.PrimitiveType = 0
    for i in 0 ..< count {
        var sum : BigIntImpl<U>.PrimitiveType = carry
        var overflow : Bool
        carry = 0
        
        if i < a.parts.count {
            (sum, overflow) = BigIntImpl<U>.PrimitiveType.addWithOverflow(sum, a.parts[i])

            if overflow {
                carry = 1
            }
        }

        if i < b.parts.count {
            (sum, overflow) = BigIntImpl<U>.PrimitiveType.addWithOverflow(sum, b.parts[i])

            if overflow {
                carry = 1
            }
        }
        
        v.parts.append(sum)
    }
    
    if carry != 0 {
        v.parts.append(carry)
    }
    
    return v
}

func -<U>(var a : BigIntImpl<U>, var b : BigIntImpl<U>) -> BigIntImpl<U>
{
    a.normalize()
    b.normalize()
    
    if a.sign != b.sign {
        if a.sign {
            return -((-a) + b)
        }
        else {
            return (a + (-b))
        }
    }
    
    if a.sign {
        return -((-a) + (-b))
    }
    
    assert(!a.sign && !b.sign)
    
    if a < b {
        return -(b - a)
    }
    
    let count = max(a.parts.count, b.parts.count)
    var v = BigIntImpl<U>(capacity: count)

    var carry = U(0)
    for i in 0 ..< count {
        var difference : U = carry
        var overflow : Bool
        carry = 0
        
        if i < a.parts.count {
            (difference, overflow) = U.subtractWithOverflow(a.parts[i], difference)
            
            if overflow {
                carry = 1
            }
        }
        
        if i < b.parts.count {
            (difference, overflow) = U.subtractWithOverflow(difference, b.parts[i])

            if overflow {
                carry = 1
            }
        }
        
        v.parts.append(difference)
    }
    
    assert(carry == 0)
    
    v.normalize()
    
    return v
}

func *<U>(var a : BigIntImpl<U>, var b : BigIntImpl<U>) -> BigIntImpl<U>
{
    let aCount = a.parts.count;
    let bCount = b.parts.count;
    let resultCount = aCount + bCount

    var result = BigIntImpl<U>(count: resultCount)
    
    for i in 0 ..< aCount {
       
        var overflow    : Bool
        
        for j in 0 ..< bCount {

            var lo      : UInt64 = 0
            var hi      : UInt64 = 0

            NSC_multiply64(a.parts[i].toUIntMax(), b.parts[j].toUIntMax(), &lo, &hi)
            
            if lo == 0 && hi == 0 {
                continue
            }
            
            if sizeof(U) < sizeof(UIntMax) {
                let shift : UIntMax = UIntMax(8 * sizeof(U))
                let mask : UIntMax = (0xffffffffffffffff >> UIntMax(64 - shift))
                hi = (lo & (mask << shift)) >> shift
                lo = lo & mask
            }
            
            (result.parts[i + j], overflow) = U.addWithOverflow(result.parts[i + j], U(lo.toUIntMax()))

            if overflow {
                hi += 1
            }
            
            var temp = hi
            var index = i + j + 1
            while true {
                (result.parts[index], overflow) = U.addWithOverflow(result.parts[index], U(temp.toUIntMax()))
                if overflow {
                    temp = 1
                    index += 1
                }
                else {
                    break
                }
            }
        }
    }

    result.normalize()
    
    result.sign = (a.sign != b.sign)

    return result
}

func *<U>(a : BigIntImpl<U>, b : Int) -> BigIntImpl<U>
{
    return a * BigIntImpl<U>(b)
}

func *<U>(a : Int, b : BigIntImpl<U>) -> BigIntImpl<U>
{
    return BigIntImpl<U>(a) * b
}

// short division
func /<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, v : UInt) -> BigIntImpl<UIntN>
{
    return u / Int(v)
}

func /<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, v : Int) -> BigIntImpl<UIntN>
{
    let UIntNShift = UIntMax(sizeof(UIntN) * 8)
    let b = UIntMax(UIntMax(1) << UIntNShift)
    var r = UIntMax(0)
    let n = u.parts.count
    let vv = UIntMax(v.toIntMax())
    
    var result = BigIntImpl<UIntN>(count: n)
    for i in (0 ..< n).reverse() {
        let t = r * b + u.parts[i].toUIntMax()
        
        let q = t / vv
        
        r = t % vv
        
        result.parts[i] = UIntN(q)
    }
    
    result.normalize()
    
    if u.sign != (v < 0) {
        result.sign = true
    }
    
    return result
}

protocol KnowsLargerIntType : UnsignedIntegerType {
    typealias LargerIntType : UnsignedIntegerType
}

extension UInt8 : KnowsLargerIntType {
    typealias LargerIntType = UInt16
}

extension UInt16 : KnowsLargerIntType {
    typealias LargerIntType = UInt32
}

extension UInt32 : KnowsLargerIntType {
    typealias LargerIntType = UInt64
}

func short_division<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, _ v : Int, inout remainder : Int?) -> BigIntImpl<UIntN>
{
    let UIntNShift = UIntMax(sizeof(UIntN) * 8)
    let b = UIntMax(UIntMax(1) << UIntNShift)
    var r = UIntMax(0)
    let n = u.parts.count
    let vv = UIntMax(v.toIntMax())
    
    var result = BigIntImpl<UIntN>(count: n)
    for i in (0 ..< n).reverse() {
        let t = r * b + u.parts[i].toUIntMax()
        
        let q = t / vv
        r = t % vv
        
        result.parts[i] = UIntN(q)
    }
    
    result.normalize()
    
    if u.sign != (v < 0) {
        result.sign = true
    }
    
    if remainder != nil {
        remainder = Int(r)
    }
    
    return result
}


func division<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, _ v : BigIntImpl<UIntN>, inout remainder : BigIntImpl<UIntN>?) -> BigIntImpl<UIntN>
{
    typealias BigIntType = BigIntImpl<UIntN>
    typealias UIntN2 = UIntN.LargerIntType
    typealias LargerBigIntType = BigIntImpl<UIntN2>
    
    let uSign = u.sign
    
    // This is an implementation of Algorithm D in
    // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
    if v.isZero {
        // handle error
        return BigIntType(0)
    }
    
    if u.isZero {
        return BigIntType(0)
    }
    
    let n = v.parts.count
    let m = u.parts.count - v.parts.count
    
    if m < 0 {
        if remainder != nil {
            remainder = u
        }

        return BigIntType(0)
    }
    
    if n == 1 && m == 0 {
        if remainder != nil {
            remainder = BigIntType(UInt((u.parts[0] % v.parts[0]).toUIntMax()), negative: u.sign)
        }
        
        return BigIntType(u.parts[0] / v.parts[0])
    }
    else if n == 1 {
        var divisor = Int(v.parts[0].toUIntMax())
        if v.sign {
            divisor = -divisor
        }

        var rem : Int? = remainder == nil ? nil : 0
        let result = short_division(u, divisor, remainder: &rem)
        
        if remainder != nil {
            remainder = BigIntImpl(rem!)
        }
        
        return result
    }

    let UIntNShift = UIntMax(sizeof(UIntN) * 8)
    let b = UIntN2(UIntMax(1) << UIntNShift)
    var u = BigIntType(u.parts)
    var v = BigIntType(v.parts)
    
    var result = BigIntType(count: m + 1)
    
    // normalize, so that v[0] >= base/2 (i.e. 2^31 in our case)
    let shift = UIntMax((sizeof(BigIntType.PrimitiveType.self) * 8) - 1)
    let highestBitMask : UIntMax = 1 << shift
    var hi = v.parts[n - 1].toUIntMax()
    var d = 1
    while (UIntN(hi) & UIntN(highestBitMask)) == 0
    {
        hi = hi << 1
        d  = d  << 1
    }

    if d != 1 {
        u = u * BigIntType(d)
        v = v * BigIntType(d)
    }
    
    if u.parts.count < m + n + 1 {
        u.parts.append(0)
    }

    for j in (0 ..< m+1).reverse()
    {
        // D3. Calculate q
        let dividend = UIntN2(u.parts[j + n].toUIntMax() << UIntNShift + u.parts[j + n - 1].toUIntMax())
        let denominator = UIntN2(v.parts[n - 1].toUIntMax())
        var q : UIntN2 = dividend / denominator
        var r : UIntN2 = dividend % denominator
        
        if q != 0 {
            var numIterationsThroughLoop = 0
            while q == b || (q.toUIntMax() * v.parts[n - 2].toUIntMax() > (r.toUIntMax() << UIntNShift + u.parts[j + n - 2].toUIntMax())) {
                
                q = q - 1
                r = r + denominator
                
                if r > b {
                    break
                }
                
                numIterationsThroughLoop += 1
                
                assert(numIterationsThroughLoop <= 2)
            }
            

            // D4. Multiply and subtract
            var vtemp = v
            vtemp.parts.append(0)
            var temp = BigIntType(u.parts[j...j+n]) - vtemp * BigIntType(q)

            // D6. handle negative case
            if temp.sign {
                // handle negative case
                temp = temp + vtemp
                q = q - 1
            }
            
            let count = temp.parts.count
            for i in 0 ..< n {
                u.parts[j + i] = i < count ? temp.parts[i] : 0
            }
        }
        
        result.parts[j] = UIntN(q.toUIntMax())
        
    }

    let q =  BigIntType(result.parts, negative: u.sign != v.sign)

    if remainder != nil {
        let uSlice = u.parts[0..<n]
        let uParts = [UIntN](uSlice)
        remainder = BigIntType(uParts, negative: uSign) / d
    }
    
    return q
}

func /<U : UnsignedIntegerType where U : KnowsLargerIntType>(var u : BigIntImpl<U>, var v : BigIntImpl<U>) -> BigIntImpl<U>
{
    // This is an implementation of Algorithm D in
    // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
    if v == BigIntImpl<U>(0) {
        // handle error
        return BigIntImpl<U>(0)
    }
    
    let n = v.parts.count
    let m = u.parts.count - v.parts.count
    
    if m < 0 {
        return BigIntImpl<U>(0)
    }
    
    if n == 1 && m == 0 {
        return BigIntImpl<U>(u.parts[0]/v.parts[0])
    }
    else if n == 1 {
        var divisor = Int(v.parts[0].toUIntMax())
        if v.sign {
            divisor = -divisor
        }
        
        return u / divisor
    }
    
    if U.self == UInt64.self {
        let uu = BigIntImpl<UInt32>(u.parts)
        let vv = BigIntImpl<UInt32>(v.parts)
        
        var remainder : BigIntImpl<UInt32>? = nil
        let result = division(uu, vv, remainder: &remainder)
        
        return BigIntImpl<U>(result)
    }
    
    var remainder : BigIntImpl<U>? = nil
    return division(u, v, remainder: &remainder)
}

func %<U : UnsignedIntegerType where U : KnowsLargerIntType>(u : BigIntImpl<U>, v : BigIntImpl<U>) -> BigIntImpl<U>
{
    var remainder : BigIntImpl<U>? = BigIntImpl<U>(0)
    division(u, v, remainder: &remainder)
    
    return remainder!
}

//func %(u : BigInt, v : BigInt) -> BigInt
//{
//    return u % v
//}

func == <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    return lhs.parts == rhs.parts && lhs.sign == rhs.sign
}

func < <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    if lhs.sign != rhs.sign {
        return lhs.sign
    }
    
    if lhs.sign {
        return -lhs > -rhs
    }
    
    if lhs.parts.count != rhs.parts.count {
        return lhs.parts.count < rhs.parts.count
    }

    if lhs.parts.count > 0 {
        for i in (0 ..< lhs.parts.count).reverse()
        {
            if lhs.parts[i] == rhs.parts[i] {
                continue
            }

            return lhs.parts[i] < rhs.parts[i]
        }
        
        return false
    }

    assert(lhs.parts.count == 0 && rhs.parts.count == 0)
    
    return false
}

func > <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    if lhs.sign != rhs.sign {
        return rhs.sign
    }
    
    if lhs.sign {
        return -lhs < -rhs
    }

    if lhs.parts.count != rhs.parts.count {
        if lhs.isZero && rhs.isZero {
            return false
        }

        return lhs.parts.count > rhs.parts.count
    }
    
    if lhs.parts.count > 0 {
        for i in (0 ..< lhs.parts.count).reverse()
        {
            if lhs.parts[i] == rhs.parts[i] {
                continue
            }
            
            return lhs.parts[i] > rhs.parts[i]
        }
        
        return false
    }
    
    assert(lhs.parts.count == 0 && rhs.parts.count == 0)
    
    return false
}

prefix func -<U>(var v : BigIntImpl<U>) -> BigIntImpl<U> {
    v.sign = !v.sign
    return v
}

func modular_multiply<U : UnsignedIntegerType where U : KnowsLargerIntType>(a : BigIntImpl<U>, b : BigIntImpl<U>, mod : BigIntImpl<U>) -> BigIntImpl<U>
{
    return ((a % mod) * (b % mod)) % mod
}

func pow<U : UnsignedIntegerType where U : KnowsLargerIntType>(base : BigIntImpl<U>, _ exponent : Int) -> BigIntImpl<U>
{
    let numBits = sizeof(Int) * 8
    
    var result = BigIntImpl<U>(1)
    var r = base
    for i in 0 ..< numBits
    {
        if (exponent & (1 << i)) != 0 {
            result = result * r
        }
        
        r = r * r
    }
    
    return result
}

