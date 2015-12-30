//
//  RSA.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum RSA_PKCS1PaddingType : UInt8
{
    case None  = 0
    case Type1 = 1
}

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
    
    init?(publicKey: [UInt8])
    {
        guard let sequence = ASN1Parser(data: publicKey).parseObject() as? ASN1Sequence else {
            return nil
        }
        
        guard sequence.objects.count == 2 else {
            return nil
        }
        
        guard let n = sequence.objects[0] as? ASN1Integer else {
            return nil
        }

        guard let e = sequence.objects[1] as? ASN1Integer else {
            return nil
        }

        self.n = BigInt(bigEndianParts: n.value)
        self.e = BigInt(bigEndianParts: e.value)

        self.d = nil
        self.p = nil
        self.q = nil
        self.exponent1 = nil
        self.exponent2 = nil
        self.coefficient = nil
    }
    
    func signData(data : [UInt8], paddingType: RSA_PKCS1PaddingType? = .Type1) -> BigInt
    {
        guard let d = self.d else {
            precondition(self.d != nil)
            return BigInt(0)
        }
        
        let paddedData = self.paddedData(data, length: self.n.numberOfBits / 8, paddingType: paddingType!)!
        
        print("padded \(paddedData)")
        
        let m = BigInt(bigEndianParts: paddedData)
        let signature = modular_pow(m, d, n)
        
        return signature
    }
    
    func verifySignature(signature : BigInt, data: [UInt8], paddingType: RSA_PKCS1PaddingType? = .Type1) -> Bool
    {
        let e = self.e
        
        let verification = modular_pow(signature, e, n)
        print("verification \(verification.asBigEndianData())")
        guard let unpaddedVerification = self.unpaddedData(verification.asBigEndianData(), length: self.n.numberOfBits / 8, paddingType: paddingType!) else {
            return false
        }
        
        print("unpadded \(unpaddedVerification)")

        guard let sequence = ASN1Parser(data: unpaddedVerification).parseObject() as? ASN1Sequence where sequence.objects.count == 2 else {
            return false
        }
        
        guard let subSequence = sequence.objects[0] as? ASN1Sequence where subSequence.objects.count >= 1 else {
            return false
        }
        
        guard
            let oidObject = subSequence.objects[0] as? ASN1ObjectIdentifier,
            let oid = OID(id: oidObject.identifier)
        else {
            return false
        }
        
        let hash : [UInt8]
        let hashedData : [UInt8]
        switch oid
        {
        case .sha1:
            guard let octetString = sequence.objects[1] as? ASN1OctetString else {
                return false
            }
            hash = octetString.value
            hashedData = Hash_SHA1(data)
            
        default:
            fatalError("Unsupported hash algorithm \(oid)")
        }

        let m = BigInt(bigEndianParts: hashedData)

        return hash == (m % n).asBigEndianData()
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
    
    private func paddedData(data : [UInt8], length: Int, paddingType : RSA_PKCS1PaddingType) -> [UInt8]?
    {
        switch paddingType
        {
        case .None:
            return data
            
        case .Type1:
            let dataLength = data.count
            if dataLength + 3 > length {
                return nil
            }
            
            var paddedData : [UInt8] = [0,1]
            let paddingLength = length - 3 - dataLength
            paddedData += [UInt8](count: paddingLength, repeatedValue: 0xff)
            paddedData += [0]
            paddedData += data
            
            return paddedData
        }
    }
    
    private func unpaddedData(paddedData : [UInt8], length: Int, paddingType : RSA_PKCS1PaddingType) -> [UInt8]?
    {
        switch paddingType
        {
        case .None:
            return paddedData
            
        case .Type1:
            guard paddedData.count + 1 == length && paddedData[0] == 1 else {
                return nil
            }
            
            // skip over padding
            var firstNonPaddingIndex : Int = 0
            for i in 1 ..< paddedData.count
            {
                if paddedData[i] == 0xff {
                    continue
                }
                
                firstNonPaddingIndex = i
                break
            }
            
            guard firstNonPaddingIndex < paddedData.count && paddedData[firstNonPaddingIndex] == 0 else {
                return nil
            }
            
            return [UInt8](paddedData[(firstNonPaddingIndex + 1) ..< paddedData.count])
        }
    }
}

extension RSA : Signing
{
    func sign(data : [UInt8]) -> [UInt8]
    {
        let signature = self.signData(data)
        
        return signature.asBigEndianData()
    }
    
    func verify(signature : [UInt8], data : [UInt8]) -> Bool
    {
        return self.verifySignature(BigInt(bigEndianParts: signature), data: data)
    }
}