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


let prime256v1_P =  BigInt(bigEndianParts: [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] as[UInt8])

let prime256v1_A =  BigInt(bigEndianParts: [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC] as [UInt8])

let prime256v1_B =  BigInt(bigEndianParts: [0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
                                            0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
                                            0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
                                            0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B] as [UInt8])

let prime256v1_Gx = BigInt(bigEndianParts: [0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
                                            0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
                                            0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
                                            0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96] as [UInt8])

let prime256v1_Gy = BigInt(bigEndianParts: [0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
                                            0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                                            0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
                                            0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5] as [UInt8])

let prime256v1_N =  BigInt(bigEndianParts: [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
                                            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51] as [UInt8])


extension EllipticCurve {
    static func named(name : NamedCurve) -> EllipticCurve?
    {
        switch name
        {
        case .secp256r1:
            return EllipticCurve(p: prime256v1_P, a: prime256v1_A, b: prime256v1_B, G: EllipticCurvePoint(x:prime256v1_Gx, y: prime256v1_Gy), n: prime256v1_N)
            
        default:
            return nil
        }
    }
}