//
//  RSA-PKCS1.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 03.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

enum RSA_PKCS1PaddingType : UInt8
{
    case none  = 0
    case type1 = 1
    case type2 = 2
}


extension RSA {
    func emsa_pkcs1_v1_5_encode(message m: [UInt8], encodedMessageLength emLen: Int) throws -> [UInt8] {
        
        let hashAlgorithm = self.algorithm.hashAlgorithm
        let hash = self.hash(m, hashAlgorithm: hashAlgorithm)
        
        let writer = ASN1Writer()
        let sequence = ASN1Sequence(objects: [
            ASN1Sequence(objects: [
                ASN1ObjectIdentifier(oid: hashAlgorithm.oid),
                ASN1Null()
                ]),
            ASN1OctetString(data: hash)
            ])
        
        let derData = writer.dataFromObject(sequence)
        let tLen = derData.count
        
        if emLen < tLen + 11 {
            throw Error.intendedEncodedMessageLengthTooShort
        }
        
        var paddedData : [UInt8] = [0,1]
        let paddingLength = emLen - tLen - 3
        paddedData += [UInt8](repeating: 0xff, count: paddingLength)
        paddedData += [0]
        paddedData += derData
        
        return paddedData
    }
    
    func eme_pkcs1_v1_5_encode(message m: [UInt8]) throws -> [UInt8] {
    
        let mLen = m.count
        let k = self.nOctetLength
        
        if mLen > k - 11 {
            throw Error.messageTooLong
        }
        
        var paddedData : [UInt8] = [0,2]
        let paddingLength = k - mLen - 3
        
        for _ in 0..<paddingLength {
            while true {
                let randomByte = UInt8.random
                if randomByte == 0 {
                    continue
                }
                
                paddedData += [randomByte]
                break
            }
        }
        paddedData += [0]
        paddedData += m
        
        return paddedData
    }
    
    func rsaes_pkcs1_v1_5_encrypt(m: [UInt8]) throws -> [UInt8] {
        let em = try eme_pkcs1_v1_5_encode(message: m)
        let m = os2ip(octetString: em)
        let c = try rsaep(m: m)
        
        return try i2osp(x: c, xLen: self.nOctetLength)
    }
    
    func rsaes_pkcs1_v1_5_decrypt(c: [UInt8]) throws -> [UInt8] {
        precondition(self.d != nil)
    
        let k = self.nOctetLength
        if c.count != k || k < 11 {
            throw Error.decryptionError
        }
        
        let encrypted = os2ip(octetString: c)
        let decrypted = try rsadp(c: encrypted)
        
        let paddedData = try i2osp(x: decrypted, xLen: k)
        
        if paddedData[0] != 0 || paddedData[1] != 2 {
            throw Error.decryptionError
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
            throw Error.decryptionError
        }
        
        return [UInt8](paddedData[(firstNonPaddingIndex + 1) ..< paddedData.count])
    }
    
    func rsassa_pkcs1_v1_5_sign(m M: [UInt8]) throws -> [UInt8] {
        let k = self.nOctetLength
        let em = try emsa_pkcs1_v1_5_encode(message: M, encodedMessageLength: k)
        let m = os2ip(octetString: em)
        let s = try rsasp1(m: m)
        return try i2osp(x: s, xLen: k)
    }

    func rsassa_pkcs1_v1_5_verify(m M: [UInt8], s S: [UInt8]) throws -> Bool {
        
        let k = self.nOctetLength
        if S.count != k {
            throw Error.invalidSignature
        }
        
        let s = os2ip(octetString: S)
        let m = try rsavp1(s: s)
        let em = try i2osp(x: m, xLen: k)
        let emDash = try emsa_pkcs1_v1_5_encode(message: M, encodedMessageLength: k)
        
        return em == emDash
    }

    func unpaddedData(_ paddedData : [UInt8], length: Int = 0) -> [UInt8]?
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
    
    func verifySignature(_ signature : BigInt, data: [UInt8]) throws -> Bool
    {
        let verification = try rsavp1(s: signature)
        
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
            hashSize = HashAlgorithm.sha1.hashLength
            
        case .sha256:
            hashedData = Hash_SHA256(data)
            hashSize = HashAlgorithm.sha256.hashLength
            
        default:
            throw TLSError.error("Unsupported hash algorithm \(oid)")
        }
        
        let m = BigInt(bigEndianParts: hashedData)
        
        guard let octetString = sequence.objects[1] as? ASN1OctetString else {
            return false
        }
        hash = octetString.value
        
        return hash == [UInt8]((m % n).asBigEndianData().suffix(hashSize))
    }
}
