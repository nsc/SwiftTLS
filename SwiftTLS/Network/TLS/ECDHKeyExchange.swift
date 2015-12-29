//
//  ECDHKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 11.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

class ECDHKeyExchange
{
    let curve : EllipticCurve
    
    var d : BigInt?
    var Q : EllipticCurvePoint?
    var peerPublicKey : EllipticCurvePoint?
    
    init(curve : EllipticCurve)
    {
        self.curve = curve
    }

    func calculatePublicKey() -> EllipticCurvePoint
    {
        let (d, Q) = self.curve.createKeyPair()
        self.d = d
        self.Q = Q
        
        return Q
    }
    
    // dA * dB * G
    func calculateSharedSecret() -> BigInt?
    {
        guard
            let d = self.d,
            let peerPublicKey = self.peerPublicKey
        else {
            return nil
        }
        
        return self.curve.multiplyPoint(peerPublicKey, d).x
    }
}
