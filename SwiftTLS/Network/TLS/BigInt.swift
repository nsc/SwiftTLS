//
//  BigInt.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.11.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftHelper

public struct BigInt : IntegerArithmeticType, IntegerLiteralConvertible
{
    typealias PrimitiveType = UInt32
    private typealias BigIntImplType = BigIntImpl<PrimitiveType>
    
    private let impl : BigIntImplType
    
    var numberOfBits : Int {
        return impl.parts.count * sizeof(BigIntImplType.PrimitiveType.self) * 8
    }
    
    var isZero : Bool {
        get {
            return impl.isZero
        }
    }

    var sign : Bool {
        get { return impl.sign }
    }
    
    func toArray<T : UnsignedIntegerType>() -> [T]
    {
        return BigIntImpl<T>(impl.parts).parts
    }
    
    func asBigEndianData() -> [UInt8]
    {
        return BigIntImpl<UInt8>(impl.parts).parts.reverse()
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

    public init<T where T : UnsignedIntegerType>(_ a : T) {
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

    private init(_ impl : BigIntImplType)
    {
        self.impl = impl
    }
    
    /// parts are given in little endian order
    public init<T where T : UnsignedIntegerType>(_ parts : [T], negative: Bool = false)
    {
        var b = BigIntImplType(parts, negative: negative)
        b.normalize()
        
        self.impl = b
    }

    public init<T where T : UnsignedIntegerType>(bigEndianParts : [T], negative: Bool = false)
    {
        var b = BigIntImplType(bigEndianParts.reverse(), negative: negative)
        b.normalize()
        
        self.impl = b
    }

    func isBitSet(bitNumber : Int) -> Bool
    {
        return impl.isBitSet(bitNumber)
    }

    static func random(max : BigInt) -> BigInt
    {
        return BigInt(BigIntImplType.random(max.impl))
    }

    // Hashable
    public var hashValue: Int {
        get {
            return impl.parts.count > 0 ? Int(impl.parts[0]) : 0
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
        precondition(impl.parts.count <= 1)
        
        return IntMax(self.impl.sign ? -1 : 1) * IntMax(impl.parts[0])
    }

    // _IntegerArithmeticType
    public static func addWithOverflow(lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs + rhs, overflow: false)
    }
    
    public static func subtractWithOverflow(lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs - rhs, overflow: false)
    }
    
    public static func multiplyWithOverflow(lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs * rhs, overflow: false)
    }
    
    public static func divideWithOverflow(lhs: BigInt, _ rhs:BigInt) -> (BigInt, overflow: Bool)
    {
        return (lhs / rhs, overflow: false)
    }
    
    public static func remainderWithOverflow(lhs: BigInt, _ rhs: BigInt) -> (BigInt, overflow: Bool)
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
        self.init("\(expr.impl)")
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
    
    modular_pow(generator, exponent, modulus)
}


/// BigInt represents arbitrary precision integers
///
/// They use largest primitive possible (usually UInt64)
/// and are stored in little endian order, i.e. n = parts[0] + parts[1] * 2^64 + parts[2] * 2 ^ 128 ...
private struct BigIntImpl<U where U : UnsignedIntegerType> {
    
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
        
        n.parts.withUnsafeMutableBufferPointer { arc4random_buf($0.baseAddress, num * sizeof(U)); return }
        
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

private func *<U>(a : BigIntImpl<U>, b : BigIntImpl<U>) -> BigIntImpl<U>
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
    associatedtype LargerIntType : UnsignedIntegerType
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

private func short_division<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, _ v : Int, inout remainder : Int?) -> BigIntImpl<UIntN>
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


private func division<UIntN : KnowsLargerIntType>(u : BigIntImpl<UIntN>, _ v : BigIntImpl<UIntN>, inout remainder : BigIntImpl<UIntN>?) -> BigIntImpl<UIntN>
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

private func /<U : UnsignedIntegerType where U : KnowsLargerIntType>(u : BigIntImpl<U>, v : BigIntImpl<U>) -> BigIntImpl<U>
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

private func %<U : UnsignedIntegerType where U : KnowsLargerIntType>(u : BigIntImpl<U>, v : BigIntImpl<U>) -> BigIntImpl<U>
{
    var remainder : BigIntImpl<U>? = BigIntImpl<U>(0)
    division(u, v, remainder: &remainder)
    
    return remainder!
}

//func %(u : BigInt, v : BigInt) -> BigInt
//{
//    return u % v
//}

private func == <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
{
    return lhs.parts == rhs.parts && lhs.sign == rhs.sign
}

private func < <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
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

private func > <U>(lhs : BigIntImpl<U>, rhs : BigIntImpl<U>) -> Bool
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

private prefix func -<U>(v : BigIntImpl<U>) -> BigIntImpl<U> {
    var v = v
    v.sign = !v.sign
    return v
}

private func modular_multiply<U : UnsignedIntegerType where U : KnowsLargerIntType>(a : BigIntImpl<U>, b : BigIntImpl<U>, mod : BigIntImpl<U>) -> BigIntImpl<U>
{
    return ((a % mod) * (b % mod)) % mod
}

private func pow<U : UnsignedIntegerType where U : KnowsLargerIntType>(base : BigIntImpl<U>, _ exponent : Int) -> BigIntImpl<U>
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

