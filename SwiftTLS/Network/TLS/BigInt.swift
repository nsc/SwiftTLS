//
//  BigInt.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.11.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public struct BigInt : IntegerArithmeticType, IntegerLiteralConvertible
{
    typealias PrimitiveType = UInt32
    typealias BigIntImplType = BigIntImpl<PrimitiveType>
    
    private let impl : BigIntImplType
    
    var numberOfBits : Int {
        return impl.parts.count * sizeof(BigIntImplType.PrimitiveType.self) * 8
    }
    
    func toArray<T : UnsignedIntegerType>() -> [T]
    {
        return BigIntImpl<T>(impl.parts).parts
    }
    
    public init(_ a : Int) {
        impl = BigIntImplType(a)
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
    init<T where T : UnsignedIntegerType>(_ parts : [T], negative: Bool = false)
    {
        self.impl = BigIntImplType(parts, negative: negative)
    }
    
    func toString() -> String
    {
        return impl.toString()
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

extension String {
    init(stringInterpolationSegment expr: BigInt) {
        self.init(expr.toString())
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
    
    print(exponent.toString())
    print(modulus.toString())
    
    modular_pow(generator, exponent, modulus)
}
