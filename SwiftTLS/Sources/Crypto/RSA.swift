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
    enum Error : Swift.Error {
        case maskTooLong
        case messageTooLong
        case encodingError
        case integerTooLarge
        case decryptionError
        case invalidSignature
        case cipherTextRepresentativeOutOfRange
        case messageRepresentativeOutOfRange
        case signatureRepresentativeOutOfRange
        case intendedEncodedMessageLengthTooShort
        
        case error(message: String)
    }

    let n : BigInt
    let e : BigInt

    let d : BigInt?
    let p : BigInt?
    let q : BigInt?
    let dP : BigInt?
    let dQ : BigInt?
    let qInv : BigInt?
    
    var algorithm: X509.SignatureAlgorithm
    
    let reducer: ModularReduction
    
    static func fromPEMFile(_ file : String) -> RSA?
    {
        var certificate: X509.Certificate? = nil
        var privateKeyRSA: RSA? = nil
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
                // FIXME: support .rsassa_pss
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
                
                privateKeyRSA = RSA(n : n, e: e, d: d, p: p, q: q, dP: exponent1, dQ: exponent2, qInv: coefficient)
                
            case "CERTIFICATE":
                if let sequence = object as? ASN1Sequence {
                    certificate = X509.Certificate(asn1Sequence: sequence)
                }
                break

            default:
                break
            }
        }
        
        if let certificate = certificate {
            if let rsa = privateKeyRSA {
                return RSA(n: rsa.n, e: rsa.e, d: rsa.d!, p: rsa.p!, q: rsa.q!, dP: rsa.dP!, dQ: rsa.dQ!, qInv: rsa.qInv!, signatureAlgorithm: certificate.signatureAlgorithm.algorithm)
            }
            else {
                return RSA(certificate: certificate)
            }
        }
        else {
            return privateKeyRSA
        }
    }
    
    init?(certificate: X509.Certificate)
    {
        self.init(publicKey: certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.bits)
        
        self.algorithm = certificate.tbsCertificate.signature.algorithm
    }
    
    private init(n : BigInt, e : BigInt, d : BigInt, p : BigInt, q : BigInt, dP : BigInt, dQ : BigInt, qInv : BigInt, signatureAlgorithm: X509.SignatureAlgorithm? = nil)
    {
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dP = dP
        self.dQ = dQ
        self.qInv = qInv
        self.algorithm = signatureAlgorithm ?? .rsa_pkcs1(hash: .sha256)
        
        self.reducer = Montgomery(modulus: self.n)
    }

    init(n: BigInt, publicExponent: BigInt, privateExponent: BigInt? = nil)
    {
        self.e = publicExponent
        self.d = privateExponent
        self.n = n
        self.p = nil
        self.q = nil
        self.dP = nil
        self.dQ = nil
        self.qInv = nil
        self.algorithm = .rsa_pkcs1(hash: .sha256)
        
        self.reducer = Montgomery(modulus: self.n)
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
        self.dP = nil
        self.dQ = nil
        self.qInv = nil
        self.algorithm = .rsa_pkcs1(hash: .sha256)
        
        self.reducer = Montgomery(modulus: self.n)
    }
    
    var nOctetLength: Int {
        let modBits = self.n.bitWidth
        let octetLength = (modBits - 1 + 7)/8
        
        return octetLength
    }
    
    func rsasp1(m: BigInt) throws -> BigInt {
        return try BigInt.withContextReturningBigInt { _ -> BigInt in
            guard m < self.n - 1 else {
                throw Error.messageRepresentativeOutOfRange
            }
        
            guard let d = self.d else {
                throw TLSError.error("Signing primitive used without a private key")
            }
        
            // FIXME: Use second form (CRT) when applicable
            let s = reducer.modular_pow(m, d)
        
            return s
        }
    }
    
    func rsavp1(s: BigInt) throws -> BigInt {
        return try BigInt.withContextReturningBigInt { _ -> BigInt in
            guard s < self.n - 1 else {
                throw Error.signatureRepresentativeOutOfRange
            }
            

            let m = reducer.modular_pow(s, e, constantTime: false)

            return m
        }
    }

    func rsaep(m: BigInt) throws -> BigInt {
        return try BigInt.withContextReturningBigInt { _ -> BigInt in
            guard m < self.n - 1 else {
                throw Error.messageRepresentativeOutOfRange
            }
            

            let c = reducer.modular_pow(m, e)

            return c
        }
    }

    func rsadp(c: BigInt) throws -> BigInt {
        return try BigInt.withContextReturningBigInt { _ -> BigInt in
            guard c < self.n - 1 else {
                throw Error.cipherTextRepresentativeOutOfRange
            }
        
            guard let d = self.d else {
                throw TLSError.error("Decryption primitive used without a private key")
            }
        
            // FIXME: Use second form (CRT) when applicable
            let m = reducer.modular_pow(c, d)
        
            return m
        }
    }

    // We are currently only supporting PKCS1 encryption, not OAEP
    func encrypt(_ data: [UInt8]) throws -> [UInt8] {
        return try rsaes_pkcs1_v1_5_encrypt(m: data)
    }
    
    func decrypt(_ data: [UInt8]) throws -> [UInt8] {
        return try rsaes_pkcs1_v1_5_decrypt(c: data)
    }
        
    func hash(_ data : [UInt8], hashAlgorithm: HashAlgorithm) -> [UInt8]
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
}

extension RSA : Signing
{
    func sign(data: [UInt8]) throws -> [UInt8]
    {
        return try BigInt.withContext { _ in
            switch self.algorithm {
                
            case .rsa_pkcs1(_):
                return try rsassa_pkcs1_v1_5_sign(m: data)
                
            case .rsassa_pss(_, _):
                return try rsassa_pss_sign(message: data)
                
            default:
                fatalError("Invalid signature scheme \(self.algorithm)")
            }
        }
    }
    
    func verify(signature : [UInt8], data : [UInt8]) throws -> Bool
    {
        return try BigInt.withContext { _ in
            switch self.algorithm {
                
            case .rsa_pkcs1(_):
                return try rsassa_pkcs1_v1_5_verify(m: data, s: signature)
                
            case .rsassa_pss(_, _):
                return try rsassa_pss_verify(message: data, signature: signature)
                
            default:
                fatalError("Invalid signature scheme \(self.algorithm)")
            }
        }
    }
}

