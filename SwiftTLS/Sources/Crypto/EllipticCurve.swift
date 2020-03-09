//
//  EllipticCurve.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 10.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public enum NamedGroup : UInt16 {
    case secp256r1 = 0x17
    case secp384r1 = 0x18
    case secp521r1 = 0x19
    
    case x25519    = 0x1d
    case x448      = 0x1e
    
    /* Finite Field Groups (DHE) */
    case ffdhe2048 = 0x0100
    case ffdhe3072 = 0x0101
    case ffdhe4096 = 0x0102
    case ffdhe6144 = 0x0103
    case ffdhe8192 = 0x0104
    
    case arbitrary_explicit_prime_curves = 0xFF01
    case arbitrary_explicit_char2_curves = 0xFF02

    var bitLength : Int {
        get {
            switch self {
            case .secp256r1:
                return 256
                
            case .secp384r1:
                return 384
                
            case .secp521r1:
                return 521

            default:
                return 0
            }
        }
    }
    
    var keyExchange: KeyExchange {
        switch self {
        case .secp256r1, .secp384r1, .secp521r1:
            guard let curve = EllipticCurve.named(self) else {
                fatalError("Elliptic Curve \(self) not defined")
            }
            
            return KeyExchange.ecdhe(ECDHKeyExchange(curve: curve))
            
        default:
            fatalError("Elliptic Curve \(self) not supported")
        }
    }
    
    init?(oid: OID)
    {
        switch oid {
        case .prime256v1:
            self = .secp256r1
            
        case .ansip521r1:
            self = .secp521r1
            
        default:
            return nil
        }
    }
    var oid: OID {
        switch self
        {
        case .secp256r1:
            return .prime256v1

        case .secp384r1:
            return .ansip384r1

        case .secp521r1:
            return .ansip521r1

        default:
            fatalError("Unknown OID for \(self)")
        }
    }
    
    init?(inputStream: InputStreamType)
    {
        guard let rawNamedCurve : UInt16 = inputStream.read() else {
            return nil
        }
        
        self.init(rawValue: rawNamedCurve)
        log("Curve: \(self)")
    }
}

extension NamedGroup : Streamable {
    public func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write(self.rawValue)
    }
}

enum ECPointFormat : UInt8 {
    case uncompressed = 0
    case ansiX962_compressed_prime = 1
    case ansiX962_compressed_char2 = 2
}

struct EllipticCurvePoint
{
    var x : BigInt
    var y : BigInt
    
    init(x: BigInt, y: BigInt)
    {
        self.x = x
        self.y = y
    }
    
    init?(data: [UInt8])
    {
        // only uncompressed format is currently supported
        if data[0] != 4 {
            log("Error: only uncompressed curve points are supported")
            return nil
        }
        
        let numBytes = data.count/2
        self.x = BigInt(bigEndianParts: [UInt8](data[1 ..< 1 + numBytes]))
        self.y = BigInt(bigEndianParts: [UInt8](data[1 + numBytes ..< 1 + 2 * numBytes]))
    }
    
    func isOnCurve(_ curve : EllipticCurve) -> Bool
    {
        return curve.isOnCurve(self)
    }
}

extension EllipticCurvePoint : Streamable {
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        let data = self.x.asBigEndianData() + self.y.asBigEndianData()
        
        target.write(UInt8(4)) // uncompressed ECPoint encoding
        target.write(data)
    }
}

func ==(a: EllipticCurvePoint, b: EllipticCurvePoint) -> Bool
{
    return a.x == b.x && a.y == b.y
}

func !=(a: EllipticCurvePoint, b: EllipticCurvePoint) -> Bool
{
    return !(a == b)
}

public protocol ModularReduction {
    var modulus: BigInt { get }
    init(modulus: BigInt)
    func reduce(_ x: BigInt) -> BigInt
    func modular_pow(_ base: BigInt, _ exponent: BigInt, constantTime: Bool) -> BigInt
    func modular_inverse(_ x : BigInt, _ y : BigInt, constantTime: Bool) -> BigInt
}

extension ModularReduction {
    public func modular_pow(_ base : BigInt, _ exponent : BigInt, constantTime: Bool = true) -> BigInt
    {
        let numBits = exponent.bitWidth
        
        var result = BigInt(1)
        var r = self.reduce(base)
        for i in 0..<numBits
        {
            let bit = BigInt(exponent.bit(at: i))
            let tmp = (constantTime || !bit.isZero) ? self.reduce(result * r) : result
            
            // Avoid branch in order to mitigate the risk of timing attacks
            result = bit * tmp + (BigInt(1) - bit) * result
            
            r = self.reduce(r * r)
        }
        
        return result
    }
    
    private func non_constantTime_modular_inverse(_ x : BigInt, _ y : BigInt) -> BigInt
    {
        let x = x > 0 ? x : x + modulus
        let y = y > 0 ? y : y + modulus

        let inverse = extended_euclid(z: y, a: modulus)

        var result = self.reduce(inverse * x)

        let zero : BigInt = 0
        if result < zero {
            result = result + modulus
        }

        return result
    }

    public func modular_inverse(_ x : BigInt, _ y : BigInt, constantTime: Bool = true) -> BigInt
    {
        if !constantTime {
            return non_constantTime_modular_inverse(x, y)
        }
        
        let x = x > 0 ? x : x + modulus
        let y = y > 0 ? y : y + modulus

        let inverse = self.modular_pow(y, modulus - BigInt(2), constantTime: constantTime)

        var result = self.reduce(inverse * x)

        let zero : BigInt = 0
        if result < zero {
            result = result + modulus
        }

        return result
    }
}

struct DefaultModularReduction : ModularReduction {
    let modulus: BigInt
    init(modulus: BigInt) {
        self.modulus = modulus
    }

    func reduce(_ x: BigInt) -> BigInt {
        let result =  x % modulus
        return result < 0 ? result + modulus : result
    }
}

// y^2 = (x^3 + a*x + b) % p
// where (4a^3 + 27b^2) % p ≢ 0
struct EllipticCurve
{
    let name: NamedGroup
    let p : BigInt
    let a : BigInt
    let b : BigInt
    let G : EllipticCurvePoint
    let n : BigInt
    
    var reducer: ModularReduction
    
    init(name: NamedGroup,
         p : BigInt,
         a : BigInt,
         b : BigInt,
         G : EllipticCurvePoint,
         n : BigInt)
    {
        self.name = name
        self.p = p
        self.a = a
        self.b = b
        self.G = G
        self.n = n

//        self.reducer = Montgomery(modulus: self.p)

        self.reducer = BarrettReduction(modulus: self.p)
//        self.reducer = DefaultModularReduction(modulus: self.p)
    }

    fileprivate func isOnCurve(_ point : EllipticCurvePoint) -> Bool
    {
        let x = point.x
        let y = point.y
        
        let lhs = (y * y) % p
        let rhs = (x * x * x + a * x + b) % p
        
        return rhs == lhs
    }
    
    func addPoints(_ p1 : EllipticCurvePoint, _ p2 : EllipticCurvePoint, constantTime: Bool = true, context: UnsafeMutablePointer<BigIntContext>? = nil) -> EllipticCurvePoint
    {
        guard p1 != p2 else {
            return doublePoint(p1, constantTime: constantTime)
        }
     
        let (x, y) = BigInt.withContextReturningBigInt(context) { context in
            
            let lambda = modular_inverse(p2.y - p1.y, p2.x - p1.x, mod: self.p, context: context)
            
            var x = (lambda * lambda - p1.x - p2.x) % self.p
            var y = (lambda * (p1.x - x) - p1.y) % self.p
            
            if x < BigInt(0) {
                x = x + self.p
            }
            
            if y < BigInt(0) {
                y = y + self.p
            }
            
            assert(x.signum() == 1)
            assert(y.signum() == 1)
        
            return (x, y)
        }
        
        return EllipticCurvePoint(x: x, y: y)
    }
    
    func doublePoint(_ p : EllipticCurvePoint, constantTime: Bool = true, context: UnsafeMutablePointer<BigIntContext>? = nil) -> EllipticCurvePoint
    {
        let (x, y) = BigInt.withContextReturningBigInt(context) { context in
            let lambda = self.reducer.modular_inverse(3 * (p.x * p.x) + self.a, 2 * p.y, constantTime: constantTime)
            
            let x = reducer.reduce(lambda * lambda - 2 * p.x)
            let y = reducer.reduce(lambda * (p.x - x) - p.y)
        
            return (x, y)
        }
        
        return EllipticCurvePoint(x: x, y: y)
    }
    
    func multiplyPoint(_ point : EllipticCurvePoint, _ d : BigInt, constantTime: Bool = true) -> EllipticCurvePoint
    {
        let (x, y) = BigInt.withContextReturningBigInt { _ in
            
            var point = point
            
            var result = EllipticCurvePoint(x: 0, y: 0)
            
            var firstBit = true
            for i in 0 ..< d.bitWidth
            {
                let bit = BigInt(d.bit(at: i))
                let notBit = BigInt(1) - bit
                
                let tmp: EllipticCurvePoint
                if firstBit && bit == 1 {
                    tmp = point
                    firstBit = false
                }
                else {
                    tmp = (constantTime || !bit.isZero) ? self.addPoints(result, point, constantTime: constantTime) : result
                }
                
                result = EllipticCurvePoint(x: bit * tmp.x + notBit * result.x,
                                            y: bit * tmp.y + notBit * result.y)
                
                point = self.doublePoint(point, constantTime: constantTime)
                
                assert(point.isOnCurve(self))
            }
            
            return (result.x, result.y)
        }
        
        return EllipticCurvePoint(x: x, y: y)
    }
    
    func createKeyPair() -> (d : BigInt, Q : EllipticCurvePoint)
    {
        var d : BigInt
        repeat {
            d = BigInt.random(self.n)
        } while d.isZero
        
        let Q = self.multiplyPoint(self.G, d)
        
        assert(isOnCurve(Q))
        
        return (d: d, Q: Q)
    }
}

struct EllipticCurveKey
{
    let d : BigInt
    let Q : EllipticCurvePoint
}

struct EllipticCurveParameters {
    let P : BigInt
    let A : BigInt
    let B : BigInt
    let G : EllipticCurvePoint
    let N : BigInt
}

extension EllipticCurve {
    static func named(_ name : NamedGroup) -> EllipticCurve?
    {
        switch name
        {
        case .secp256r1:
            return EllipticCurve(
                name: .secp256r1,
                p: BigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", radix: 16)!,
                a: BigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", radix: 16)!,
                b: BigInt("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", radix: 16)!,
                G: EllipticCurvePoint(
                    x: BigInt("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", radix: 16)!,
                    y: BigInt("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", radix: 16)!
                ),
                n: BigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", radix: 16)!
            )
            
        case .secp384r1:
            return EllipticCurve(
                name: .secp384r1,
                p: BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", radix: 16)!,
                a: BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", radix: 16)!,
                b: BigInt("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", radix: 16)!,
                G: EllipticCurvePoint(
                    x: BigInt("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", radix: 16)!,
                    y: BigInt("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", radix: 16)!
                ),
                n: BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", radix: 16)!
            )

            
        case .secp521r1:
            return EllipticCurve(
                name: .secp521r1,
                p: BigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", radix: 16)!,
                a: BigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", radix: 16)!,
                b: BigInt("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", radix: 16)!,
                G: EllipticCurvePoint(
                    x: BigInt("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", radix: 16)!,
                    y: BigInt("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", radix: 16)!
                ),
                n: BigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", radix: 16)!
            )

            
        default:
            return nil
        }
    }
}
