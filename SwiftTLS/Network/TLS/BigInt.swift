//
//  BigInt.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.11.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftHelper

public struct BigInt : IntegerArithmetic, ExpressibleByIntegerLiteral
{
    typealias PrimitiveType = UInt32
    private typealias BigIntImplType = BigIntImpl<PrimitiveType>
    
    fileprivate let impl : BigIntImplType
    
    var numberOfBits : Int {
        return impl.bits.count * MemoryLayout<BigIntImplType.PrimitiveType>.size * 8
    }
    
    var isZero : Bool {
        get {
            return impl.isZero
        }
    }

    var sign : Bool {
        get { return impl.sign }
    }
    
    func toArray<T : UnsignedInteger>() -> [T]
    {
        return BigIntImpl<T>(impl.bits).bits
    }
    
    func asBigEndianData() -> [UInt8]
    {
        return BigIntImpl<UInt8>(impl.bits, normalized: false).bits.reversed()
    }

    public init(_ a : Int) {
        impl = BigIntImplType(a)
    }
    
    init(_ a : UInt, negative: Bool = false) {
        impl = BigIntImpl([a], negative: negative)
    }

    public init(integerLiteral value: Int)
    {
        self.init(value)
    }

    public init<T : UnsignedInteger>(_ a : T) {
        impl = BigIntImplType([a])
    }
    
    public init(count: Int)
    {
        impl = BigIntImplType(count: count)
    }
    
    public init(capacity: Int) {
        impl = BigIntImplType(capacity: capacity)
    }
    
    public init?(hexString : String, negative : Bool = false)
    {
        guard let impl = BigIntImplType(hexString: hexString, negative: negative)
        else {
            return nil
        }
        
        self.impl = impl
    }

    fileprivate init(_ impl : BigIntImplType)
    {
        self.impl = impl
    }
    
    /// parts are given in little endian order
    public init<T : UnsignedInteger>(_ parts : [T], negative: Bool = false)
    {
        var b = BigIntImplType(parts, negative: negative)
        b.normalize()
        
        self.impl = b
    }

    public init<T : UnsignedInteger>(bigEndianParts : [T], negative: Bool = false)
    {
        var b = BigIntImplType(bigEndianParts.reversed(), negative: negative)
        b.normalize()
        
        self.impl = b
    }

    func isBitSet(_ bitNumber : Int) -> Bool
    {
        return impl.isBitSet(bitNumber)
    }

    static func random(_ max : BigInt) -> BigInt
    {
        return BigInt(BigIntImplType.random(max.impl))
    }

    // Hashable
    public var hashValue: Int {
        get {
            return impl.bits.count > 0 ? Int(impl.bits[0]) : 0
        }
    }

    // _Incrementable
    public func successor() -> BigInt {
        return self + BigInt(1)
    }
    
    /// Explicitly convert to `IntMax`, trapping on overflow (except in
    /// -Ounchecked builds).
    public func toIntMax() -> IntMax
    {
        // Our primitive type is UInt32, so we could represent more than just one
        // part. Since toIntMax isn't all too useful in the general case and will
        // trap anyway, we don't care about that right now.
        precondition(impl.bits.count <= 1)
        
        return IntMax(self.impl.sign ? -1 : 1) * IntMax(impl.bits[0])
    }

    // _IntegerArithmeticType
    public static func addWithOverflow(_ lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs + rhs, overflow: false)
    }
    
    public static func subtractWithOverflow(_ lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs - rhs, overflow: false)
    }
    
    public static func multiplyWithOverflow(_ lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs * rhs, overflow: false)
    }
    
    public static func divideWithOverflow(_ lhs: BigInt, _ rhs:BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs / rhs, overflow: false)
    }
    
    public static func remainderWithOverflow(_ lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs % rhs, overflow: false)
    }
}

extension BigInt : CustomStringConvertible
{
    public var description : String {
        return "\(self)"
    }
}

extension String {
    init(stringInterpolationSegment expr: BigInt) {
        self = "\(expr.impl)"
    }
}

public func ==(lhs : BigInt, rhs : BigInt) -> Bool
{
    return lhs.impl == rhs.impl
}

// Comparable
public func <(lhs: BigInt, rhs: BigInt) -> Bool
{
    return lhs.impl < rhs.impl
}

public func <=(lhs: BigInt, rhs: BigInt) -> Bool
{
    return lhs.impl == rhs.impl || lhs.impl < rhs.impl
}

public func >=(lhs: BigInt, rhs: BigInt) -> Bool
{
    return lhs.impl == rhs.impl || lhs.impl > rhs.impl
}

public func >(lhs: BigInt, rhs: BigInt) -> Bool
{
    return lhs.impl > rhs.impl
}

// IntegerArithmeticType

public func +(lhs : BigInt, rhs : BigInt) -> BigInt
{
    return BigInt(lhs.impl + rhs.impl)
}

public func -(lhs : BigInt, rhs : BigInt) -> BigInt
{
    return BigInt(lhs.impl - rhs.impl)
}

public func *(lhs: BigInt, rhs: BigInt) -> BigInt
{
    return BigInt(lhs.impl * rhs.impl)
}

public func /(lhs: BigInt, rhs: BigInt) -> BigInt
{
    return BigInt(lhs.impl / rhs.impl)
}

public func %(lhs: BigInt, rhs: BigInt) -> BigInt
{
    return BigInt(lhs.impl % rhs.impl)
}

// Integer Compatibility

public func +(lhs : Int, rhs : BigInt) -> BigInt
{
    return BigInt(lhs) + BigInt(rhs.impl)
}

public func -(lhs : Int, rhs : BigInt) -> BigInt
{
    return BigInt(lhs) - BigInt(rhs.impl)
}

public func *(lhs: Int, rhs: BigInt) -> BigInt
{
    return BigInt(lhs) * BigInt(rhs.impl)
}

public func /(lhs: Int, rhs: BigInt) -> BigInt
{
    return BigInt(lhs) / BigInt(rhs.impl)
}

public func %(lhs: Int, rhs: BigInt) -> BigInt
{
    return BigInt(lhs) % BigInt(rhs.impl)
}

public func +(lhs : BigInt, rhs : Int) -> BigInt
{
    return BigInt(lhs.impl) + BigInt(rhs)
}

public func -(lhs : BigInt, rhs : Int) -> BigInt
{
    return BigInt(lhs.impl) - BigInt(rhs)
}

public func *(lhs: BigInt, rhs: Int) -> BigInt
{
    return BigInt(lhs.impl) * BigInt(rhs)
}

public func /(lhs: BigInt, rhs: Int) -> BigInt
{
    return BigInt(lhs.impl) / BigInt(rhs)
}

public func %(lhs: BigInt, rhs: Int) -> BigInt
{
    return BigInt(lhs.impl) % BigInt(rhs)
}



func SwiftTLS_mod_pow_performance()
{
    let generator = BigInt([2] as [UInt32], negative: false)
    let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
    let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"
    
    
    let exponent = BigInt(hexString: exponentString)!
    let modulus = BigInt(hexString: modulusString)!
    
    print("\(exponent)")
    print("\(modulus)")
    
    _ = modular_pow(generator, exponent, modulus)
}


/// BigInt represents arbitrary precision integers
///
/// They use largest primitive possible (usually UInt64)
/// and are stored in little endian order, i.e. n = parts[0] + parts[1] * 2^64 + parts[2] * 2 ^ 128 ...
private struct BigIntImpl<U : UnsignedInteger> {
    
    typealias PrimitiveType = U
    var bits: [PrimitiveType]
    var sign : Bool
    
    init(_ a : Int) {
        self.init([UInt(abs(a))], negative: a < 0)
    }
    
    init(_ a : UInt, negative: Bool = false) {
        self.init([a], negative: negative)
    }
    
    init<T : UnsignedInteger>(_ a : T) {
        self.init([a])
    }
    
    init(count: Int)
    {
        bits = [PrimitiveType](repeating: 0, count: count)
        sign = false
    }
    
    init(capacity: Int) {
        bits = [PrimitiveType]()
        bits.reserveCapacity(capacity)
        sign = false
    }
    
    init<T : UnsignedInteger>(_ bigInt : BigIntImpl<T>)
    {
        self.init(bigInt.bits, negative: bigInt.sign)
    }
    
    /// parts are given in little endian order
    init<T : UnsignedInteger>(_ parts : [T], negative: Bool = false, normalized: Bool = true)
    {
        let numberInPrimitiveType = MemoryLayout<PrimitiveType>.size/MemoryLayout<T>.size
        
        if numberInPrimitiveType == 1 {
            self.bits = parts.map({PrimitiveType($0.toUIntMax())})
            self.sign = negative
            return
        }
        
        if numberInPrimitiveType > 0 {
            
            var number = [PrimitiveType](repeating: 0, count: parts.count / numberInPrimitiveType + ((parts.count % MemoryLayout<PrimitiveType>.size == 0) ? 0 : 1))
            var index = 0
            var numberIndex = 0
            var n : UIntMax = 0
            var shift = UIntMax(0)
            
            for a in parts
            {
                n = n + a.toUIntMax() << shift
                shift = shift + UIntMax(MemoryLayout<T>.size * 8)
                
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
            self.bits = number
        }
        else {
            // T is a larger type than PrimitiveType
            let n = MemoryLayout<T>.size/MemoryLayout<PrimitiveType>.size
            var number = [PrimitiveType]()
            
            for a in parts
            {
                let shift : UIntMax = UIntMax(8 * MemoryLayout<PrimitiveType>.size)
                var mask : UIntMax = (0xffffffffffffffff >> UIntMax(64 - shift))
                for i in 0 ..< n
                {
                    let part : PrimitiveType = PrimitiveType((a.toUIntMax() & mask) >> (UIntMax(i) * shift))
                    number.append(part)
                    mask = mask << shift
                }
            }
            
            if normalized {
                while number.last != nil && number.last! == 0 {
                    number.removeLast()
                }
            }
            
            self.bits = number
        }
        
        self.sign = negative
    }
    
    init<T : UnsignedInteger>(_ parts : ArraySlice<T>, negative: Bool = false)
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
        
        self.init(bytes.reversed(), negative: negative)
        self.normalize()
    }
    
    mutating func normalize()
    {
        while bits.last != nil && bits.last! == 0 {
            bits.removeLast()
        }
    }
    
    var isZero : Bool {
        get {
            return bits.count == 0 || (bits.count == 1 && bits[0] == 0)
        }
    }
    
    func isBitSet(_ bitNumber : Int) -> Bool
    {
        let partSize    = MemoryLayout<PrimitiveType>.size * 8
        let partNumber  = bitNumber / partSize
        let bit         = bitNumber % partSize
        
        guard partNumber < self.bits.count else {
            return false
        }
        
        return (self.bits[partNumber].toUIntMax() & (UIntMax(1) << UIntMax(bit))) != 0
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
    
    static func random<U : KnowsLargerIntType>(_ max : BigIntImpl<U>) -> BigIntImpl<U>
    {
        let num = max.bits.count
        var n = BigIntImpl<U>(count: num)
        
        n.bits.withUnsafeMutableBufferPointer { arc4random_buf($0.baseAddress, num * MemoryLayout<U>.size); return }
        
        n.normalize()
        
        n = n % max
        
        return n
    }
}

private extension String {
    init<T>(stringInterpolationSegment expr : BigIntImpl<T>)
    {
        var s = expr.sign ? "-" : ""
        var onlyZeroesYet = true
        let count = Int(expr.bits.count)
        
        for i in (0..<count).reversed()
        {
            let part = expr.bits[i].toUIntMax()
            var c : UInt8
            
            var shift = (MemoryLayout<BigIntImpl<T>.PrimitiveType>.size - 1) * 8
            var mask : UIntMax = UIntMax(0xff) << UIntMax(shift)
            for _ in 0 ..< MemoryLayout<BigIntImpl<T>.PrimitiveType>.size
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
        
        self = s
    }
}

extension BigIntImpl : CustomStringConvertible
{
    var description : String {
        return "\(self)"
    }
}

private func +<U>(a : BigIntImpl<U>, b : BigIntImpl<U>) -> BigIntImpl<U>
{
    if a.sign != b.sign {
        if a.sign {
            return b - (-a)
        }
        else {
            return a - (-b)
        }
    }
    
    let count = max(a.bits.count, b.bits.count)
    var v = BigIntImpl<U>(capacity: count)
    v.sign = a.sign
    
    var carry : BigIntImpl<U>.PrimitiveType = 0
    for i in 0 ..< count {
        var sum : BigIntImpl<U>.PrimitiveType = carry
        var overflow : Bool
        carry = 0
        
        if i < a.bits.count {
            (sum, overflow) = BigIntImpl<U>.PrimitiveType.addWithOverflow(sum, a.bits[i])
            
            if overflow {
                carry = 1
            }
        }
        
        if i < b.bits.count {
            (sum, overflow) = BigIntImpl<U>.PrimitiveType.addWithOverflow(sum, b.bits[i])
            
            if overflow {
                carry = 1
            }
        }
        
        v.bits.append(sum)
    }
    
    if carry != 0 {
        v.bits.append(carry)
    }
    
    return v
}

private func -<U>(a : BigIntImpl<U>, b : BigIntImpl<U>) -> BigIntImpl<U>
{
    var a = a
    var b = b
    
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
    
    let count = max(a.bits.count, b.bits.count)
    var v = BigIntImpl<U>(capacity: count)
    
    var carry = U(0)
    for i in 0 ..< count {
        var difference : U = carry
        var overflow : Bool
        carry = 0
        
        if i < a.bits.count {
            (difference, overflow) = U.subtractWithOverflow(a.bits[i], difference)
            
            if overflow {
                carry = 1
            }
        }
        
        if i < b.bits.count {
            (difference, overflow) = U.subtractWithOverflow(difference, b.bits[i])
            
            if overflow {
                carry = 1
            }
        }
        
        v.bits.append(difference)
    }
    
    assert(carry == 0)
    
    v.normalize()
    
    return v
}

private func *<U>(a : BigIntImpl<U>, b : BigIntImpl<U>) -> BigIntImpl<U>
{
    let aCount = a.bits.count;
    let bCount = b.bits.count;
    let resultCount = aCount + bCount
    
    var result = BigIntImpl<U>(count: resultCount)
    
    for i in 0 ..< aCount {
        
        var overflow    : Bool
        
        for j in 0 ..< bCount {
            
            var lo      : UInt64 = 0
            var hi      : UInt64 = 0
            
            NSC_multiply64(a.bits[i].toUIntMax(), b.bits[j].toUIntMax(), &lo, &hi)
            
            if lo == 0 && hi == 0 {
                continue
            }
            
            if MemoryLayout<U>.size < MemoryLayout<UIntMax>.size {
                let shift : UIntMax = UIntMax(8 * MemoryLayout<U>.size)
                let mask : UIntMax = (0xffffffffffffffff >> UIntMax(64 - shift))
                hi = (lo & (mask << shift)) >> shift
                lo = lo & mask
            }
            
            (result.bits[i + j], overflow) = U.addWithOverflow(result.bits[i + j], U(lo.toUIntMax()))
            
            if overflow {
                hi += 1
            }
            
            var temp = hi
            var index = i + j + 1
            while true {
                (result.bits[index], overflow) = U.addWithOverflow(result.bits[index], U(temp.toUIntMax()))
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

private func *<U>(a : BigIntImpl<U>, b : Int) -> BigIntImpl<U>
{
    return a * BigIntImpl<U>(b)
}

private func *<U>(a : Int, b : BigIntImpl<U>) -> BigIntImpl<U>
{
    return BigIntImpl<U>(a) * b
}

// short division
private func /<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, v : UInt) -> BigIntImpl<UIntN>
{
    return u / Int(v)
}

private func /<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, v : Int) -> BigIntImpl<UIntN>
{
    let UIntNShift = UIntMax(MemoryLayout<UIntN>.size * 8)
    let b = UIntMax(UIntMax(1) << UIntNShift)
    var r = UIntMax(0)
    let n = u.bits.count
    let vv = UIntMax(v.toIntMax())
    
    var result = BigIntImpl<UIntN>(count: n)
    for i in (0 ..< n).reversed() {
        let t = r * b + u.bits[i].toUIntMax()
        
        let q = t / vv
        
        r = t % vv
        
        result.bits[i] = UIntN(q)
    }
    
    result.normalize()
    
    if u.sign != (v < 0) {
        result.sign = true
    }
    
    return result
}

protocol KnowsLargerIntType : UnsignedInteger {
    associatedtype LargerIntType : UnsignedInteger
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

private func short_division<UIntN : KnowsLargerIntType>(_ u : BigIntImpl<UIntN>, _ v : Int, remainder : inout Int?) -> BigIntImpl<UIntN>
{
    let UIntNShift = UIntMax(MemoryLayout<UIntN>.size * 8)
    let b = UIntMax(UIntMax(1) << UIntNShift)
    var r = UIntMax(0)
    let n = u.bits.count
    let vv = UIntMax(v.toIntMax())
    
    var result = BigIntImpl<UIntN>(count: n)
    for i in (0 ..< n).reversed() {
        let t = r * b + u.bits[i].toUIntMax()
        
        let q = t / vv
        r = t % vv
        
        result.bits[i] = UIntN(q)
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


private func division<UIntN : KnowsLargerIntType>(_ u : BigIntImpl<UIntN>, _ v : BigIntImpl<UIntN>, remainder : inout BigIntImpl<UIntN>?) -> BigIntImpl<UIntN>
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
    
    let n = v.bits.count
    let m = u.bits.count - v.bits.count
    
    if m < 0 {
        if remainder != nil {
            remainder = u
        }
        
        return BigIntType(0)
    }
    
    if n == 1 && m == 0 {
        if remainder != nil {
            remainder = BigIntType(UInt((u.bits[0] % v.bits[0]).toUIntMax()), negative: u.sign)
        }
        
        return BigIntType(u.bits[0] / v.bits[0])
    }
    else if n == 1 {
        var divisor = Int(v.bits[0].toUIntMax())
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
    
    let UIntNShift = UIntMax(MemoryLayout<UIntN>.size * 8)
    let b = UIntN2(UIntMax(1) << UIntNShift)
    var u = BigIntType(u.bits)
    var v = BigIntType(v.bits)
    
    var result = BigIntType(count: m + 1)
    
    // normalize, so that v[0] >= base/2 (i.e. 2^31 in our case)
    let shift = UIntMax((MemoryLayout<BigIntType.PrimitiveType>.size * 8) - 1)
    let highestBitMask : UIntMax = 1 << shift
    var hi = v.bits[n - 1].toUIntMax()
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
    
    if u.bits.count < m + n + 1 {
        u.bits.append(0)
    }
    
    for j in (0 ..< m+1).reversed()
    {
        // D3. Calculate q
        let dividend = UIntN2(u.bits[j + n].toUIntMax() << UIntNShift + u.bits[j + n - 1].toUIntMax())
        let denominator = UIntN2(v.bits[n - 1].toUIntMax())
        var q : UIntN2 = dividend / denominator
        var r : UIntN2 = dividend % denominator
        
        if q != 0 {
            var numIterationsThroughLoop = 0
            while q == b || (q.toUIntMax() * v.bits[n - 2].toUIntMax() > (r.toUIntMax() << UIntNShift + u.bits[j + n - 2].toUIntMax())) {
                
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
            vtemp.bits.append(0)
            var temp = BigIntType(u.bits[j...j+n]) - vtemp * BigIntType(q)
            
            // D6. handle negative case
            if temp.sign {
                // handle negative case
                temp = temp + vtemp
                q = q - 1
            }
            
            let count = temp.bits.count
            for i in 0 ..< n {
                u.bits[j + i] = i < count ? temp.bits[i] : 0
            }
        }
        
        result.bits[j] = UIntN(q.toUIntMax())
        
    }
    
    let q =  BigIntType(result.bits, negative: u.sign != v.sign)
    
    if remainder != nil {
        let uSlice = u.bits[0..<n]
        let uParts = [UIntN](uSlice)
        remainder = BigIntType(uParts, negative: uSign) / d
    }
    
    return q
}

private func /<U : UnsignedInteger>(u : BigIntImpl<U>, v : BigIntImpl<U>) -> BigIntImpl<U> where U : KnowsLargerIntType
{
    // This is an implementation of Algorithm D in
    // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
    if v == BigIntImpl<U>(0) {
        // handle error
        return BigIntImpl<U>(0)
    }
    
    let n = v.bits.count
    let m = u.bits.count - v.bits.count
    
    if m < 0 {
        return BigIntImpl<U>(0)
    }
    
    if n == 1 && m == 0 {
        return BigIntImpl<U>(u.bits[0]/v.bits[0])
    }
    else if n == 1 {
        var divisor = Int(v.bits[0].toUIntMax())
        if v.sign {
            divisor = -divisor
        }
        
        return u / divisor
    }
    
    if U.self == UInt64.self {
        let uu = BigIntImpl<UInt32>(u.bits)
        let vv = BigIntImpl<UInt32>(v.bits)
        
        var remainder : BigIntImpl<UInt32>? = nil
        let result = division(uu, vv, remainder: &remainder)
        
        return BigIntImpl<U>(result)
    }
    
    var remainder : BigIntImpl<U>? = nil
    return division(u, v, remainder: &remainder)
}

private func %<U : UnsignedInteger>(u : BigIntImpl<U>, v : BigIntImpl<U>) -> BigIntImpl<U> where U : KnowsLargerIntType
{
    var remainder : BigIntImpl<U>? = BigIntImpl<U>(0)
    _ = division(u, v, remainder: &remainder)
    
    return remainder!
}

//func %(u : BigInt, v : BigInt) -> BigInt
//{
//    return u % v
//}

private func == <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    return lhs.bits == rhs.bits && lhs.sign == rhs.sign
}

private func < <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    if lhs.sign != rhs.sign {
        return lhs.sign
    }
    
    if lhs.sign {
        return -lhs > -rhs
    }
    
    if lhs.bits.count != rhs.bits.count {
        return lhs.bits.count < rhs.bits.count
    }
    
    if lhs.bits.count > 0 {
        for i in (0 ..< lhs.bits.count).reversed()
        {
            if lhs.bits[i] == rhs.bits[i] {
                continue
            }
            
            return lhs.bits[i] < rhs.bits[i]
        }
        
        return false
    }
    
    assert(lhs.bits.count == 0 && rhs.bits.count == 0)
    
    return false
}

private func > <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    if lhs.sign != rhs.sign {
        return rhs.sign
    }
    
    if lhs.sign {
        return -lhs < -rhs
    }
    
    if lhs.bits.count != rhs.bits.count {
        if lhs.isZero && rhs.isZero {
            return false
        }
        
        return lhs.bits.count > rhs.bits.count
    }
    
    if lhs.bits.count > 0 {
        for i in (0 ..< lhs.bits.count).reversed()
        {
            if lhs.bits[i] == rhs.bits[i] {
                continue
            }
            
            return lhs.bits[i] > rhs.bits[i]
        }
        
        return false
    }
    
    assert(lhs.bits.count == 0 && rhs.bits.count == 0)
    
    return false
}

private prefix func -<U>(v : BigIntImpl<U>) -> BigIntImpl<U> {
    var v = v
    v.sign = !v.sign
    return v
}

private func modular_multiply<U : UnsignedInteger>(_ a : BigIntImpl<U>, b : BigIntImpl<U>, mod : BigIntImpl<U>) -> BigIntImpl<U> where U : KnowsLargerIntType
{
    return ((a % mod) * (b % mod)) % mod
}

private func pow<U : UnsignedInteger>(_ base : BigIntImpl<U>, _ exponent : Int) -> BigIntImpl<U> where U : KnowsLargerIntType
{
    let numBits = MemoryLayout<Int>.size * 8
    
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

