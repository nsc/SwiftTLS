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
    
    var peerPublicValue : BigInt?
    
    init(primeModulus : BigInt, generator : BigInt)
    {
        self.primeModulus   = primeModulus
        self.generator      = generator
    }
    
    func calculatePublicValue(secret : BigInt) -> BigInt
    {
        print("calculatePublicValue")
        print("\(self.generator)")
        print("\(secret)")
        print("\(primeModulus)")
        return modular_pow(self.generator, secret, primeModulus)
    }
    
    func calculateSharedSecret(secret : BigInt) -> BigInt?
    {
        guard let peerPublicValue = self.peerPublicValue else {
            return nil
        }
        
        return modular_pow(peerPublicValue, secret, self.primeModulus)
    }
}