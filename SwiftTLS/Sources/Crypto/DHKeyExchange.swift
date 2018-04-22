//
//  DHKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 02.08.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public class DHKeyExchange
{
    let primeModulus    : BigInt
    let generator       : BigInt
    
    var privateKey : BigInt?
    var Ys : BigInt?
    var Yc : BigInt?
    

    init(dhParameters: DiffieHellmanParameters)
    {
        self.primeModulus = dhParameters.p
        self.generator = dhParameters.g
        self.Ys = dhParameters.Ys
    }
    
    init(primeModulus : BigInt, generator : BigInt)
    {
        self.primeModulus   = primeModulus
        self.generator      = generator
    }
    
    func createKeyPair()
    {
        self.privateKey = BigInt.random(self.primeModulus)
        self.Ys = modular_pow(self.generator, self.privateKey!, primeModulus)
    }
    
    func calculatePublicKey() -> BigInt
    {
        assert(self.privateKey == nil)
        
        createKeyPair()
        
        return self.Ys!
    }
    
    func calculateSharedSecret() -> BigInt?
    {
        guard let peerPublicKey = self.Yc else {
            return nil
        }
        
        
        if self.privateKey == nil {
            self.createKeyPair()
        }
        
        assert(peerPublicKey != self.privateKey!)
        
        return modular_pow(peerPublicKey, self.privateKey!, self.primeModulus)
    }
}

extension DHKeyExchange : PFSKeyExchange
{
    var publicKey: [UInt8]? {
        return self.Ys?.asBigEndianData()
    }
    
    var peerPublicKey: [UInt8]? {
        get {
            guard let peerPublicKey = self.Yc else { return nil }
            
            return peerPublicKey.asBigEndianData()
        }
        
        set {
            guard let value = newValue else { return }
            
            self.Yc = BigInt(bigEndianParts: value)
        }
    }
    func calculateSharedSecret() -> [UInt8]? {
        guard self.Yc != nil else { return nil }

        return self.calculateSharedSecret()?.asBigEndianData()
    }
}
