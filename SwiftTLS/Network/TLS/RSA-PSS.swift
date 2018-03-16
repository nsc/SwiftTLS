//
//  RSA-PSS.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 04.03.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

// FIXME: Look this up. This currently serves as a placeholder only
let saltLength = 8

extension RSA {
    enum Error : Swift.Error {
        case maskTooLong
        case messageTooLong
        case encodingError
        case integerTooLarge
        case messageRepresentativeOutOfRange
        case signatureRepresentativeOutOfRange
    }
    
    func ssa_pss_sign(message: [UInt8]) throws -> [UInt8] {
        let modBits = self.n.bitWidth
        let em = try emsa_pss_encode(message: message,
                                     encodedMessageBits: modBits - 1,
                                     saltLength: saltLength)
        let m = os2ip(octetString: em)
        let s = try rsasp1(m: m)
        let k = (modBits + 7)/8
        
        return try i2osp(x: s, xLen: k)
    }
    
    func ssa_pss_verify(message: [UInt8], signature: [UInt8]) throws -> Bool {
        let s = os2ip(octetString: signature)
        let m: BigInt
        do { m = try rsavp1(s: s) } catch { return false }
        let modBits = self.n.bitWidth
        let emLen = (modBits - 1 + 7)/8
        let em: [UInt8]
        do { em = try i2osp(x: m, xLen: emLen) } catch { return false }
        
        return emsa_pss_verify(message: message, encodedMessage: em,
                               encodedMessageBits: modBits - 1, saltLength: saltLength)
    }
    
    func os2ip(octetString: [UInt8]) -> BigInt {
        return BigInt(bigEndianParts: octetString)
    }
    
    func i2osp(x: BigInt, xLen: Int) throws -> [UInt8] {
        var octetString = x.asBigEndianData()

        var paddingLength = xLen - octetString.count
        if paddingLength < 0 {
            // Remove leading zeroes in excess of xLen
            let nonZeroOctetString = octetString.drop(while: {$0 == 0})
            if nonZeroOctetString.count <= xLen {
                paddingLength = xLen - nonZeroOctetString.count
                octetString = [UInt8](nonZeroOctetString)
            }
            else {
                throw Error.integerTooLarge
            }
        }
        
        octetString = [UInt8](repeating: 0, count: paddingLength) + octetString
        
        return octetString
    }
    
    func mgf1(mgfSeed: [UInt8], maskLen: Int) throws -> [UInt8] {
        let hashAlgorithm = signatureScheme.hashAlgorithm!
        let hLen = hashAlgorithm.hashLength
        let hashFunction = hashAlgorithm.hashFunction
        
        if maskLen > (1 << 32) * hLen {
            throw Error.maskTooLong
        }
        
        var t = [UInt8]()
        for counter in 0..<(maskLen + hLen - 1)/hLen {
            let c = try i2osp(x: BigInt(counter), xLen: 4)
            t = t + hashFunction(mgfSeed + c)
        }
        
        return [UInt8](t[0..<maskLen])
    }
    
    // RFC 3447: 9.1.1 Encoding operation
    func emsa_pss_encode(message m: [UInt8], encodedMessageBits emBits: Int,
                         saltLength sLen: Int) throws -> [UInt8]
    {
        let emLen = (emBits + 7)/8
        let hashAlgorithm = signatureScheme.hashAlgorithm!
        let hLen = hashAlgorithm.hashLength
        if emLen < hLen + sLen + 2 {
            throw Error.encodingError
        }
        
        let mHash = self.hash(m, hashAlgorithm: hashAlgorithm)

        let salt = TLSRandomBytes(count: sLen)
        print("encode: salt = \(salt)")

        let mDash = [UInt8](repeating: 0, count: 8) + mHash + salt
        print("encode: mDash = \(mDash)")
        let h = self.hash(mDash, hashAlgorithm: hashAlgorithm)
        let ps = [UInt8](repeating: 0, count: emLen - sLen - hLen - 2)
        let db = ps + [0x01 as UInt8] + salt
        let dbMask = try mgf1(mgfSeed: h, maskLen: emLen - hLen - 1)
        var maskedDB = db ^ dbMask
        
        print("encode: db = \(db)")
        print("encode: maskedDB = \(maskedDB)")
        
        // Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
        // maskedDB to zero.
        let leadingZeroBits = UInt8(8 * emLen - emBits)
        assert(leadingZeroBits < 8)
        maskedDB[0] &= 0xff as UInt8 >> leadingZeroBits
        
        let em = maskedDB + h + [0xbc as UInt8]
        
        return em
    }
    
    func emsa_pss_verify(message m: [UInt8], encodedMessage em: [UInt8],
                         encodedMessageBits emBits: Int,
                         saltLength sLen: Int) -> Bool
    {
        let emLen = (emBits + 7)/8
        let hashAlgorithm = signatureScheme.hashAlgorithm!
        let hLen = hashAlgorithm.hashLength
        if emLen < hLen + sLen + 2 {
            return false
        }
        
        if em.last! != 0xbc {
            return false
        }
        let mHash = self.hash(m, hashAlgorithm: hashAlgorithm)
        let maskedDB = [UInt8](em[0..<emLen - hLen - 1])
        let h = [UInt8](em[emLen - hLen - 1..<emLen - 1])
        
        // If the leftmost 8 * emLen - emBits bits of the leftmost octet in
        // maskedDB are not all equal to zero, return false
        let leadingZeroBits = UInt8(8 * emLen - emBits)
        assert(leadingZeroBits < 8)
        if maskedDB[0] & ((0xff as UInt8) << (UInt8(8) - leadingZeroBits)) != 0 {
            return false
        }

        print("verify: maskedDB = \(maskedDB)")

        let dbMask: [UInt8]
        do {
            dbMask = try mgf1(mgfSeed: h, maskLen: emLen - hLen - 1)
        }
        catch {
            return false
        }
        
        var db = maskedDB ^ dbMask

        // Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
        // DB to zero.
        db[0] &= 0xff as UInt8 >> leadingZeroBits

        print("verify: db = \(db)")

        // Check that the leftmost emLen - hLen - sLen - 2 octets of db are zero
        for b in db[0..<emLen - hLen - sLen - 2] {
            if b != 0 {
                print("leftmost \(emLen - hLen - sLen - 2) bits of db are not zero")
                return false
            }
        }
        
        if db[emLen - hLen - sLen - 2] != 0x01 {
            print("db[\(emLen - hLen - sLen - 2)] == \(db[emLen - hLen - sLen])")
            return false
        }
        
        let salt = [UInt8](db.suffix(sLen))
        print("verify: salt = \(salt)")
        let mDash = [UInt8](repeating: 0, count: 8) + mHash + salt
        print("verify: mDash = \(mDash)")
        let hDash = self.hash(mDash, hashAlgorithm: hashAlgorithm)
        
        return h == hDash
    }
}
