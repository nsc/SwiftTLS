//
//  RSA.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

struct RSA
{
    let n : BigInt
    let e : BigInt

    let d : BigInt?
    let p : BigInt?
    let q : BigInt?
    let exponent1 : BigInt?
    let exponent2 : BigInt?
    let coefficient : BigInt?
    
    static func fromCertificateFile(file : String) -> RSA?
    {
        for (section, object) in ASN1Parser.sectionsFromPEMFile(file)
        {
            switch section
            {
            case "RSA PRIVATE KEY":
                // RSAPrivateKey ::= SEQUENCE {
                //     version           Version,
                //     modulus           INTEGER,  -- n
                //     publicExponent    INTEGER,  -- e
                //     privateExponent   INTEGER,  -- d
                //     prime1            INTEGER,  -- p
                //     prime2            INTEGER,  -- q
                //     exponent1         INTEGER,  -- d mod (p-1)
                //     exponent2         INTEGER,  -- d mod (q-1)
                //     coefficient       INTEGER,  -- (inverse of q) mod p
                //     otherPrimeInfos   OtherPrimeInfos OPTIONAL
                // }

                guard let sequence = object as? ASN1Sequence else {
                    return nil
                }
                
                let objects = sequence.objects
                let n           = BigInt(bigEndianParts:(objects[1] as! ASN1Integer).value)
                let e           = BigInt(bigEndianParts:(objects[2] as! ASN1Integer).value)
                let d           = BigInt(bigEndianParts:(objects[3] as! ASN1Integer).value)
                let p           = BigInt(bigEndianParts:(objects[4] as! ASN1Integer).value)
                let q           = BigInt(bigEndianParts:(objects[5] as! ASN1Integer).value)
                let exponent1   = BigInt(bigEndianParts:(objects[6] as! ASN1Integer).value)
                let exponent2   = BigInt(bigEndianParts:(objects[7] as! ASN1Integer).value)
                let coefficient = BigInt(bigEndianParts:(objects[8] as! ASN1Integer).value)
                
                let rsa = RSA(n : n, e: e, d: d, p: p, q: q, exponent1: exponent1, exponent2: exponent2, coefficient: coefficient)
                
                return rsa

            default:
                break
            }

        }
        
        return nil
    }
    
    private init(n : BigInt, e : BigInt, d : BigInt, p : BigInt, q : BigInt, exponent1 : BigInt, exponent2 : BigInt, coefficient : BigInt)
    {
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.exponent1 = exponent1
        self.exponent2 = exponent2
        self.coefficient = coefficient
    }

    init(n: BigInt, publicExponent: BigInt, privateExponent: BigInt? = nil)
    {
        self.e = publicExponent
        self.d = privateExponent
        self.n = n
        self.p = nil
        self.q = nil
        self.exponent1 = nil
        self.exponent2 = nil
        self.coefficient = nil
    }
    
    func signData(data : [UInt8]) -> BigInt
    {
        guard let d = self.d else {
            precondition(self.d != nil)
            return BigInt(0)
        }
        
        let m = BigInt(bigEndianParts: data)
        let signature = modular_pow(m, d, n)
        
        return signature
    }
    
    func verifySignature(signature : BigInt, data: [UInt8]) -> Bool
    {
        let e = self.e
        let m = BigInt(bigEndianParts: data)
        
        let verification = modular_pow(signature, e, n)
        
        return verification == m % n
    }

    func encrypt(data: [UInt8]) -> [UInt8]
    {
        let m = BigInt(bigEndianParts: data) % n
        let encrypted = modular_pow(m, e, n)
        
        return encrypted.asBigEndianData()
    }
    
    func decrypt(data: [UInt8]) -> [UInt8]
    {
        precondition(self.d != nil)
        
        let encrypted = BigInt(bigEndianParts: data) % n
        let decrypted = modular_pow(encrypted, d!, n)
        
        return decrypted.asBigEndianData()
    }
}