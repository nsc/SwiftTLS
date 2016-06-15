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
    var publicKey : BigInt?
    var peerPublicKey : BigInt?
    

    init(dhParameters: DiffieHellmanParameters)
    {
        self.primeModulus = dhParameters.p
        self.generator = dhParameters.g
        self.publicKey = dhParameters.Ys
    }
    
    init(primeModulus : BigInt, generator : BigInt)
    {
        self.primeModulus   = primeModulus
        self.generator      = generator
    }
    
    func calculatePublicKey() -> BigInt
    {
        assert(self.privateKey == nil)
        
        self.privateKey = BigInt.random(self.primeModulus)
        
        return modular_pow(self.generator, self.privateKey!, primeModulus)
    }
    
    func calculateSharedSecret() -> BigInt?
    {
        guard let peerPublicKey = self.peerPublicKey else {
            return nil
        }
        
        
        if self.privateKey == nil {
            print("Recalculate private key")
            _ = self.calculatePublicKey()
        }
        
        assert(peerPublicKey != self.privateKey!)
        
        return modular_pow(peerPublicKey, self.privateKey!, self.primeModulus)
    }
}
