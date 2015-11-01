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
}

// y^2 = (x^3 + a*x + b) % p
struct EllipticCurve
{
    let p : BigInt
    let a : BigInt
    let b : BigInt
    let G : EllipticCurvePoint

    func add_points(p1 : EllipticCurvePoint, p2 : EllipticCurvePoint) -> EllipticCurvePoint
    {
        let lambda = modular_inverse(p2.y - p1.y, p2.x - p1.x, mod: self.p)
        
        let x = (lambda * lambda - p1.x - p2.x) % self.p
        let y = (lambda * (p1.x - x) - p1.y) % self.p
        
        return EllipticCurvePoint(x: x, y: y)
    }
    
    func double_point(p1 : EllipticCurvePoint) -> EllipticCurvePoint
    {
        let lambda = modular_inverse(3 * (p1.x * p1.x) + self.a, 2 * p1.y, mod: self.p)

        let x = (lambda * lambda - 2 * p1.x) % self.p
        let y = (lambda * (p1.x - x) - p1.y) % self.p
        
        return EllipticCurvePoint(x: x, y: y)
    }
}

