//
//  ECDSA.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

struct ECDSA : Signing
{
    var algorithm: X509.SignatureAlgorithm {
        return .ecPublicKey(curveName: self.curve.name.oid, hash: hashAlgorithm)
    }
    
    var curve : EllipticCurve
    
    var privateKey : BigInt?
    var publicKey : EllipticCurvePoint
    var hashAlgorithm: HashAlgorithm
    
    init(curve: EllipticCurve, publicKey: EllipticCurvePoint, privateKey: BigInt? = nil)
    {
        self.curve = curve
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.hashAlgorithm = .sha256
    }
    
    init?(publicKeyInfo : X509.SubjectPublicKeyInfo)
    {
        assert(publicKeyInfo.subjectPublicKey.bits.count * 8 == publicKeyInfo.subjectPublicKey.numberOfBits)

        let algorithmIdentifier = publicKeyInfo.algorithm
        guard case .ecPublicKey(let curveName, let hashAlgorithm) = algorithmIdentifier.algorithm else { return nil }
     
        switch (curveName, hashAlgorithm)
        {
        case (.ansip521r1, .sha256):
            self.curve = EllipticCurve.named(.secp521r1)!
            self.hashAlgorithm = hashAlgorithm

        case (.ecdsa_secp256r1, .sha256):
            self.curve = EllipticCurve.named(.secp256r1)!
            self.hashAlgorithm = hashAlgorithm

        default:
            log("Unknown curve \(curveName)")
            return nil
        }

        guard let publicKey = EllipticCurvePoint(data: publicKeyInfo.subjectPublicKey.bits) else { return nil }
        self.publicKey = publicKey
    }
    
    func sign(data : [UInt8]) -> (BigInt, BigInt)
    {
        assert(self.privateKey != nil)
        
        var s : BigInt = BigInt(0)
        var r : BigInt
        repeat {
            let G = curve.G
            let n = curve.n
            let z = BigInt(bigEndianParts: data)
            let d = self.privateKey!
            
            let k = BigInt.random(n)
            let P = curve.multiplyPoint(G, k)
            r = P.x % n
            
            if r.isZero {
                continue
            }
            
            let kInverse = modular_inverse(1, k, mod: n)
            s = (kInverse * (z + r * d)) % n

        } while s.isZero
        
        return (r, s)
    }
    
    func sign(data: [UInt8]) throws -> [UInt8] {
        let (r, s) = sign(data: data)
        
        let point = ASN1Sequence(objects: [
            ASN1Integer(value: r.asBigEndianData()),
            ASN1Integer(value: s.asBigEndianData())
            ])
        
        let writer = ASN1Writer()
        let signatureData = writer.dataFromObject(point)
        
        return signatureData
    }
    
    func verify(signature: [UInt8], data: [UInt8]) -> Bool
    {
        guard let points = ASN1Parser(data: signature).parseObject() as? ASN1Sequence else { return false }
        guard points.objects.count == 2 else { return false }
        guard let r = points.objects[0] as? ASN1Integer else { return false }
        guard let s = points.objects[1] as? ASN1Integer else { return false }
        
        return self.verify(signature: (BigInt(bigEndianParts: r.value), BigInt(bigEndianParts: s.value)), data: data)
    }
    
    func verify(signature : (BigInt, BigInt), data: [UInt8]) -> Bool
    {
        let n = curve.n
        let G = curve.G
        let z = BigInt(bigEndianParts: data)
        let (r, s) = signature
        let H = self.publicKey
        
        let sInverse = modular_inverse(BigInt(1), s, mod:n)
        let u1 = (sInverse * z) % n
        let u2 = (sInverse * r) % n
        let P = curve.addPoints(curve.multiplyPoint(G, u1), curve.multiplyPoint(H, u2))
        
        let verification = P.x % n
                
        return (r == verification)
    }
}

extension ECDSA {
    public static func fromPEMFile(_ file : String) -> ECDSA?
    {
        var certificate: X509.Certificate? = nil
        var privateKeyECDSA: BigInt? = nil
        var publicKey: EllipticCurvePoint? = nil
        var curve: EllipticCurve? = nil
        var namedCurveFromECParameters: OID? = nil
        var namedCurveFromPrivateKeyInfo: OID? = nil
        
        for (section, object) in ASN1Parser.sectionsFromPEMFile(file)
        {
            switch section
            {
            case "EC PARAMETERS":
                if let oid = object as? ASN1ObjectIdentifier,
                    let identifier = oid.oid {
                    namedCurveFromECParameters = identifier
                    switch identifier {
                    case .ecdsa_secp256r1:
                        curve = secp256r1
                    default:
                        log("Unsupported curve \(identifier)")
                    }
                }
                else {
                    log("Unsupported curve \(object)")
                }
                break
                
            case "EC PRIVATE KEY":
                //  ECPrivateKey ::= SEQUENCE {
                //      version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                //      privateKey OCTET STRING,
                //      parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
                //      publicKey [1] BIT STRING OPTIONAL
                //  }
                guard let sequence = object as? ASN1Sequence else {
                    break
                }
                
                let objects     = sequence.objects
                guard objects.count >= 2 else {
                    break
                }
                
                guard let version = (objects[0] as? ASN1Integer)?.intValue, version == 1 else {
                    break
                }
                
                guard let privateKeyOctetString = (objects[1] as? ASN1OctetString) else {
                    break
                }
                
                privateKeyECDSA = BigInt(bigEndianParts: privateKeyOctetString.value)
                
                if objects.count > 2 {
                    if  let taggedObject = (objects[2] as? ASN1TaggedObject), taggedObject.tag == 0,
                        let namedCurveOID = (taggedObject.object as? ASN1ObjectIdentifier)?.oid {
                        namedCurveFromPrivateKeyInfo = namedCurveOID
                    }
                    else {
                        log("Unsupported ECDomainParameter \(objects[2])")
                        break
                    }
                }
                
                if objects.count > 3 {
                    if  let taggedObject = (objects[3] as? ASN1TaggedObject), taggedObject.tag == 1,
                        let ecPublicKeyBitString = taggedObject.object as? ASN1BitString, let ecPublicKey = EllipticCurvePoint(data: ecPublicKeyBitString.value) {
                        publicKey = ecPublicKey
                    }
                }
                
            case "CERTIFICATE":
                if let sequence = object as? ASN1Sequence {
                    certificate = X509.Certificate(asn1Sequence: sequence)
                }
                break
                
            default:
                break
            }
        }
        
        if  let namedCurveFromECParameters = namedCurveFromECParameters,
            let namedCurveFromPrivateKeyInfo = namedCurveFromPrivateKeyInfo {
            
            if namedCurveFromECParameters != namedCurveFromPrivateKeyInfo {
                log("Curve OID from EC PARAMETERS does not match the one from EC PRIVATE KEY")
                return nil
            }
        }
        
        var ecdsa: ECDSA? = nil
        if  let privateKey = privateKeyECDSA,
            let curve = curve,
            let publicKey = publicKey {
                ecdsa = ECDSA(curve: curve, publicKey: publicKey, privateKey: privateKey)
        }

        return ecdsa
    }
}

