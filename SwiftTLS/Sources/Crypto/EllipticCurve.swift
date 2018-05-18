//
//  EllipticCurve.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 10.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public enum NamedGroup : UInt16 {
    case secp256r1 = 23
    case secp384r1 = 24
    case secp521r1 = 25
    
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
    
    fileprivate func isOnCurve(_ point : EllipticCurvePoint) -> Bool
    {
        let x = point.x
        let y = point.y
        
        let lhs = (y * y) % p
        let rhs = (x * x * x + a * x + b) % p
        
        return rhs == lhs
    }
    
    func addPoints(_ p1 : EllipticCurvePoint, _ p2 : EllipticCurvePoint) -> EllipticCurvePoint
    {
        assert(p1 != p2)
        
        let lambda = modular_inverse(p2.y - p1.y, p2.x - p1.x, mod: self.p)
        
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

        return EllipticCurvePoint(x: x, y: y)
    }
    
    func doublePoint(_ p : EllipticCurvePoint) -> EllipticCurvePoint
    {
        let lambda = modular_inverse(3 * (p.x * p.x) + self.a, 2 * p.y, mod: self.p)

        var x = (lambda * lambda - 2 * p.x) % self.p
        var y = (lambda * (p.x - x) - p.y) % self.p
        
        if x < BigInt(0) {
            x = x + self.p
        }

        if y < BigInt(0) {
            y = y + self.p
        }

        assert(x.signum() == 1)
        assert(y.signum() == 1)

        return EllipticCurvePoint(x: x, y: y)
    }
    
    func multiplyPoint(_ point : EllipticCurvePoint, _ d : BigInt) -> EllipticCurvePoint
    {
        var point = point
        
        var result : EllipticCurvePoint? = nil
        
        for i in 0 ..< d.bitWidth
        {
            if d.isBitSet(i) {
                if result != nil {
                    result = self.addPoints(result!, point)
                }
                else {
                    result = point
                }
            }

            point = self.doublePoint(point)
            
            assert(point.isOnCurve(self))
        }
        
        return result!
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

let secp256r1 = EllipticCurve(
    name: .secp256r1,
    p: BigInt(hexString: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")!,
    a: BigInt(hexString: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")!,
    b: BigInt(hexString: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")!,
    G: EllipticCurvePoint(
        x: BigInt(hexString: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")!,
        y: BigInt(hexString: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")!
    ),
    n: BigInt(hexString: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")!
    )

let secp384r1 = EllipticCurve(
    name: .secp384r1,
    p: BigInt(hexString: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF")!,
    a: BigInt(hexString: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")!,
    b: BigInt(hexString: "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")!,
    G: EllipticCurvePoint(
        x: BigInt(hexString: "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7")!,
        y: BigInt(hexString: "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")!
    ),
    n: BigInt(hexString: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")!
)

let secp521r1 = EllipticCurve(
    name: .secp521r1,
    p: BigInt(hexString: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")!,
    a: BigInt(hexString: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")!,
    b: BigInt(hexString: "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")!,
    G: EllipticCurvePoint(
        x: BigInt(hexString: "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66")!,
        y: BigInt(hexString: "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")!
    ),
    n: BigInt(hexString: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")!
)


extension EllipticCurve {
    static func named(_ name : NamedGroup) -> EllipticCurve?
    {
        switch name
        {
        case .secp256r1:
            return secp256r1
            
        case .secp384r1:
            return secp384r1
            
        case .secp521r1:
            return secp521r1
            
        default:
            return nil
        }
    }
}
