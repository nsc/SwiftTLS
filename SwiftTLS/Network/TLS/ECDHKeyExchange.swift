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
    var peerPublicKeyPoint : EllipticCurvePoint?
    
    init(curve : EllipticCurve)
    {
        self.curve = curve
    }

    func calculatePublicKeyPoint() -> EllipticCurvePoint
    {
        createKeyPair()
        
        return self.Q!
    }
    
    // dA * dB * G
    func calculateSharedSecret() -> BigInt?
    {
        guard
            let d = self.d,
            let peerPublicKeyPoint = self.peerPublicKeyPoint
        else {
            return nil
        }
        
        return self.curve.multiplyPoint(peerPublicKeyPoint, d).x
    }
    
    func createKeyPair() {
        let (d, Q) = self.curve.createKeyPair()
    
        self.d = d
        self.Q = Q
    }
}

extension ECDHKeyExchange : PFSKeyExchange
{
    var publicKey: [UInt8]? {
        get {
            guard let Q = self.Q else {
                return nil
            }
            
            return [UInt8](Q)
        }
    }

    var peerPublicKey: [UInt8]? {
        get {
            guard let peerPublicKeyPoint = self.peerPublicKeyPoint else { return nil }
            
            return [UInt8](peerPublicKeyPoint)
        }
        
        set {
            if let value = newValue {
                self.peerPublicKeyPoint = EllipticCurvePoint(data: value)
            }
        }
    }
    func calculateSharedSecret() -> [UInt8]? {
        guard self.peerPublicKeyPoint != nil else { return nil }
        
        return (self.calculateSharedSecret() as BigInt?)?.asBigEndianData()
    }
}
