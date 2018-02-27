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
    case none  = 0
    case type1 = 1
    case type2 = 2
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
    
    static func fromPEMFile(_ file : String) -> RSA?
    {
        for (section, var object) in ASN1Parser.sectionsFromPEMFile(file)
        {
            switch section
            {
            case "PRIVATE KEY":
                // PrivateKeyInfo ::= SEQUENCE {
                //     version         Version,
                //     algorithm       AlgorithmIdentifier,
                //     PrivateKey      BIT STRING
                // }
                //
                // AlgorithmIdentifier ::= SEQUENCE {
                //     algorithm       OBJECT IDENTIFIER,
                //     parameters      ANY DEFINED BY algorithm OPTIONAL
                // }
                guard let sequence = object as? ASN1Sequence else {
                    return nil
                }

                let objects     = sequence.objects
                guard objects.count == 3 else {
                    return nil
                }

                let algorithmIdentifier = (sequence.objects[1] as! ASN1Sequence)
                let algorithm = (algorithmIdentifier.objects[0] as! ASN1ObjectIdentifier).identifier
                guard let oid = OID(id: algorithm), oid == .rsaEncryption else {
                    return nil
                }
                
                var data: [UInt8]
                if let bitString = (objects[2] as? ASN1BitString) {
                    data = bitString.value
                }
                else if let octetString = (objects[2] as? ASN1OctetString) {
                    data = octetString.value
                }
                else {
                    return nil
                }
                guard let rsaPrivateKey = ASN1Parser(data: data).parseObject() else {
                    return nil
                }
                
                object = rsaPrivateKey
                
                fallthrough
                
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
                
                let objects     = sequence.objects
                guard objects.count == 9 else {
                    return nil
                }
                
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

            case "CERTIFICATE":
                break

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
    
    func signData(_ data : [UInt8], hashAlgorithm: HashAlgorithm) -> BigInt
    {
        guard let d = self.d else {
            precondition(self.d != nil)
            return BigInt(0)
        }
        
        print("signData with n = \(self.n)")
        
        let hash = self.hash(data, hashAlgorithm: hashAlgorithm)
        
        let writer = ASN1Writer()
        let sequence = ASN1Sequence(objects: [
            ASN1Sequence(objects: [
                ASN1ObjectIdentifier(oid: self.oidForHashAlgorithm(hashAlgorithm)),
                ASN1Null()
                ]),
            ASN1OctetString(data: hash)
            ])
        
        let derData = writer.dataFromObject(sequence)
        
        let paddedData = self.paddedData(derData, paddingType: .type1)!
        
        let m = BigInt(bigEndianParts: paddedData)
        let signature = modular_pow(m, d, n)
        
        return signature
    }
    
    func verifySignature(_ signature : BigInt, data: [UInt8]) -> Bool
    {
        let e = self.e
        
        let verification = modular_pow(signature, e, n)
        
        guard let unpaddedVerification = self.unpaddedData(verification.asBigEndianData()) else {
            return false
        }
        
        guard let sequence = ASN1Parser(data: unpaddedVerification).parseObject() as? ASN1Sequence, sequence.objects.count == 2 else {
            return false
        }

        guard let subSequence = sequence.objects[0] as? ASN1Sequence, subSequence.objects.count >= 1 else {
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
        let hashSize: Int
        switch oid
        {
        case .sha1:
            hashedData = Hash_SHA1(data)
            hashSize = HashAlgorithm.sha1.size
            
        case .sha256:
            hashedData = Hash_SHA256(data)
            hashSize = HashAlgorithm.sha256.size

        default:
            fatalError("Unsupported hash algorithm \(oid)")
        }

        let m = BigInt(bigEndianParts: hashedData)

        guard let octetString = sequence.objects[1] as? ASN1OctetString else {
            return false
        }
        hash = octetString.value
                
        return hash == [UInt8]((m % n).asBigEndianData().suffix(hashSize))
    }

    func encrypt(_ data: [UInt8]) -> [UInt8]
    {
        let padded = paddedData(data, paddingType: .type2)!
        let m = BigInt(bigEndianParts: padded) % n
        let encrypted = modular_pow(m, e, n)
        
        return encrypted.asBigEndianData()
    }
    
    func decrypt(_ data: [UInt8]) -> [UInt8]
    {
        precondition(self.d != nil)
        
        let encrypted = BigInt(bigEndianParts: data) % n
        let decrypted = modular_pow(encrypted, d!, n)
        
        let paddedData = decrypted.asBigEndianData()
        
        return unpaddedData(paddedData)!
    }
    
    private func paddedData(_ data : [UInt8], length: Int = 0, paddingType : RSA_PKCS1PaddingType) -> [UInt8]?
    {
        var length = length
        if length == 0 {
            length = self.n.bitWidth / 8
        }
        

        switch paddingType
        {
        case .none:
            return data
            
        case .type1:
            let dataLength = data.count
            if dataLength + 3 > length {
                return nil
            }
            
            var paddedData : [UInt8] = [0,1]
            let paddingLength = length - 3 - dataLength
            paddedData += [UInt8](repeating: 0xff, count: paddingLength)
            paddedData += [0]
            paddedData += data
            
            return paddedData

        case .type2:
            let dataLength = data.count
            if dataLength + 3 > length {
                return nil
            }
            
            var paddedData : [UInt8] = [0,2]
            let paddingLength = length - 3 - dataLength
            
            for _ in 0..<paddingLength {
                var randomNumber : UInt32
                while true {
                    randomNumber = arc4random()
                    let randomByte = UInt8(UInt(randomNumber) & UInt(0xff))
                    if randomByte == 0 {
                        continue
                    }
                    
                    paddedData += [randomByte]
                    break
                }
            }
            paddedData += [0]
            paddedData += data
            
            return paddedData

        }
    }
    
    private func unpaddedData(_ paddedData : [UInt8], length: Int = 0) -> [UInt8]?
    {
        var length = length
        if length == 0 {
            length = self.n.bitWidth / 8
        }

        var paddingType = RSA_PKCS1PaddingType.none
        if paddedData.count > 3 {
            if paddedData[0] == 0 {
                switch paddedData[1] {
                case 1:
                    paddingType = .type1
                case 2:
                    paddingType = .type2
                default:
                    paddingType = .none
                }
            }
        }
        
        switch paddingType
        {
        case .none:
            return paddedData
            
        case .type1:
            guard paddedData.count == length else {
                return nil
            }
            
            // skip over padding
            var firstNonPaddingIndex : Int = 0
            for i in 2 ..< paddedData.count
            {
                if paddedData[i] == 0xff {
                    continue
                }
                
                firstNonPaddingIndex = i
                break
            }
            
            // FIXME: Check that we have the minimum amount of necessary padding
            
            guard firstNonPaddingIndex < paddedData.count && paddedData[firstNonPaddingIndex] == 0 else {
                return nil
            }
            
            return [UInt8](paddedData[(firstNonPaddingIndex + 1) ..< paddedData.count])

        case .type2:
            guard paddedData.count == length else {
                return nil
            }
            
            // skip over padding
            var firstNonPaddingIndex : Int = 0
            for i in 2 ..< paddedData.count
            {
                if paddedData[i] != 0 {
                    continue
                }
                
                firstNonPaddingIndex = i
                break
            }
            
            // FIXME: Check that we have the minimum amount of necessary padding
            
            guard firstNonPaddingIndex < paddedData.count && paddedData[firstNonPaddingIndex] == 0 else {
                return nil
            }
            
            return [UInt8](paddedData[(firstNonPaddingIndex + 1) ..< paddedData.count])
        }
    }
    
    private func oidForHashAlgorithm(_ hashAlgorithm : HashAlgorithm) -> OID
    {
        switch hashAlgorithm
        {
//        case .MD5:
//            return Hash_MD5(data)
            
        case .sha1:
            return OID.sha1

        case .sha256:
            return OID.sha256

//        case .SHA224:
//            return Hash_SHA224(data)
//            
//        case .SHA256:
//            return Hash_SHA256(data)
//            
//        case .SHA384:
//            return Hash_SHA384(data)
//            
//        case .SHA512:
//            return Hash_SHA512(data)
            
        default:
            fatalError("Unsupported hash algorithm \(hashAlgorithm)")
        }
    }
    
    private func hash(_ data : [UInt8], hashAlgorithm: HashAlgorithm) -> [UInt8]
    {
        switch hashAlgorithm
        {
        case .md5:
            return Hash_MD5(data)
            
        case .sha1:
            return Hash_SHA1(data)
            
        case .sha224:
            return Hash_SHA224(data)
            
        case .sha256:
            return Hash_SHA256(data)
            
        case .sha384:
            return Hash_SHA384(data)
            
        case .sha512:
            return Hash_SHA512(data)
            
        default:
            fatalError("Unsupported hash algorithm \(hashAlgorithm)")
        }
    }
}

extension RSA : Signing
{
    func sign(data : [UInt8], hashAlgorithm: HashAlgorithm) -> [UInt8]
    {
        let signature = self.signData(data, hashAlgorithm: hashAlgorithm)
        
        return signature.asBigEndianData()
    }
    
    func verify(signature : [UInt8], data : [UInt8]) -> Bool
    {
        return self.verifySignature(BigInt(bigEndianParts: signature), data: data)
    }
}
