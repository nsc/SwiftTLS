//
//  EllipticCurve.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 10.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

enum NamedCurve : UInt16 {
    case sect163k1 = 1
    case sect163r1 = 2
    case sect163r2 = 3
    case sect193r1 = 4
    case sect193r2 = 5
    case sect233k1 = 6
    case sect233r1 = 7
    case sect239k1 = 8
    case sect283k1 = 9
    case sect283r1 = 10
    case sect409k1 = 11
    case sect409r1 = 12
    case sect571k1 = 13
    case sect571r1 = 14
    case secp160k1 = 15
    case secp160r1 = 16
    case secp160r2 = 17
    case secp192k1 = 18
    case secp192r1 = 19
    case secp224k1 = 20
    case secp224r1 = 21
    case secp256k1 = 22
    case secp256r1 = 23
    case secp384r1 = 24
    case secp521r1 = 25

    case arbitrary_explicit_prime_curves = 0xFF01
    case arbitrary_explicit_char2_curves = 0xFF02
    
    var bitLength : Int {
        get {
            switch self {
            case secp160k1:
                return 160
                
            case secp160r1:
                return 160
                
            case secp160r2:
                return 160
                
            case secp192k1:
                return 192

            case secp192r1:
                return 192
                
            case secp224k1:
                return 224
                
            case secp224r1:
                return 224
            
            case secp256k1:
                return 256

            case secp256r1:
                return 256
                
            case secp384r1:
                return 384
                
            case secp521r1:
                return 521

            default:
                return 0
            }
        }
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
    
    func isOnCurve(curve : EllipticCurve) -> Bool
    {
        return curve.isOnCurve(self)
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
    let p : BigInt
    let a : BigInt
    let b : BigInt
    let G : EllipticCurvePoint
    let n : BigInt
    
    private func isOnCurve(point : EllipticCurvePoint) -> Bool
    {
        let x = point.x
        let y = point.y
        
        let lhs = (y * y) % p
        let rhs = (x * x * x + a * x + b) % p
        
        return rhs == lhs
    }
    
    func addPoints(p1 : EllipticCurvePoint, _ p2 : EllipticCurvePoint) -> EllipticCurvePoint
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

        assert(!x.sign)
        assert(!y.sign)

        return EllipticCurvePoint(x: x, y: y)
    }
    
    func doublePoint(p : EllipticCurvePoint) -> EllipticCurvePoint
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

        assert(!x.sign)
        assert(!y.sign)
        
        return EllipticCurvePoint(x: x, y: y)
    }
    
    func multiplyPoint(point : EllipticCurvePoint, _ d : BigInt) -> EllipticCurvePoint
    {
        var point = point
        
        var result : EllipticCurvePoint? = nil
        
        for i in 0 ..< d.numberOfBits
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
        let d : BigInt
        var localD : BigInt
        repeat {
            localD = BigInt.random(self.n)
        } while localD.isZero
        
        d = localD
        
        let Q = self.multiplyPoint(self.G, d)
        
        let onCurve = isOnCurve(Q)
        
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

let prime192v1_P =  BigInt(bigEndianParts: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] as [UInt8])

let prime192v1_A =  BigInt(bigEndianParts: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC] as [UInt8])

let prime192v1_B =  BigInt(bigEndianParts: [0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7,
                                            0x0F, 0xA7, 0xE9, 0xAB, 0x72, 0x24, 0x30, 0x49,
                                            0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1] as [UInt8])

let prime192v1_Gx = BigInt(bigEndianParts: [0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6,
                                            0x7C, 0xBF, 0x20, 0xEB, 0x43, 0xA1, 0x88, 0x00,
                                            0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12] as [UInt8])

let prime192v1_Gy = BigInt(bigEndianParts: [0x07, 0x19, 0x2B, 0x95, 0xFF, 0xC8, 0xDA, 0x78,
                                            0x63, 0x10, 0x11, 0xED, 0x6B, 0x24, 0xCD, 0xD5,
                                            0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11] as [UInt8])

let prime192v1_N =  BigInt(bigEndianParts: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36,
                                            0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31] as [UInt8])


let secp256r1 = EllipticCurve(
    p: BigInt(hexString: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")!,
    a: BigInt(hexString: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")!,
    b: BigInt(hexString: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")!,
    G: EllipticCurvePoint(
        x: BigInt(hexString: "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")!,
        y: BigInt(hexString: "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")!
    ),
    n: BigInt(hexString: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")!
    )

let secp521r1 = EllipticCurve(
    p: BigInt(hexString: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")!,
    a: BigInt(hexString: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")!,
    b: BigInt(hexString: "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")!,
    G: EllipticCurvePoint(
        x: BigInt(hexString: "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66")!,
        y: BigInt(hexString: "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")!
    ),
    n: BigInt(hexString: "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D0899C47AEBB6FB71E91386409")!
)


extension EllipticCurve {
    static func named(name : NamedCurve) -> EllipticCurve?
    {
        switch name
        {
        case .secp256r1:
            return secp256r1
            
//        case .secp384r1:
//            break
            
        case .secp521r1:
            return secp521r1
            
        default:
            return nil
        }
    }
}