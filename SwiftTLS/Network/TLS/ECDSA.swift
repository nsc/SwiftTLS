//
//  ECDSA.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

struct ECDSA
{
    let curve : EllipticCurve
    
    var privateKey : BigInt?
    var publicKey : EllipticCurvePoint
    
    init(curve: EllipticCurve, publicKey: EllipticCurvePoint, privateKey: BigInt? = nil)
    {
        self.curve = curve
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
    
    func signData(data : [UInt8]) -> (BigInt, BigInt)
    {
        assert(self.privateKey != nil)
        
        var s : BigInt = 0
        var r : BigInt
        repeat {
            let G = curve.G
            let n = curve.n
            let z = BigInt(bigEndianParts: data)
            let d = self.privateKey!
            
            let k = BigInt.random(n)
            let P = curve.multiplyPoint(G, k)
            r = P.x % n
            
            if r.isZero {
                continue
            }
            
            let kInverse = modular_inverse(1, k, mod: n)
            s = (kInverse * (z + r * d)) % n

        } while s.isZero
        
        return (r, s)
    }
    
    func verifySignature(signature : (BigInt, BigInt), data: [UInt8]) -> Bool
    {
        let n = curve.n
        let G = curve.G
        let z = BigInt(bigEndianParts: data)
        let (r, s) = signature
        let H = self.publicKey
        
        let sInverse = modular_inverse(1, s, mod:n)
        let u1 = (sInverse * z) % n
        let u2 = (sInverse * r) % n
        let P = curve.addPoints(curve.multiplyPoint(G, u1), curve.multiplyPoint(H, u2))
        
        return (r == P.x % n)
    }
}

