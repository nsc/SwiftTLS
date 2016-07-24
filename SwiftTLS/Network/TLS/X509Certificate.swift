//
//  X509Certificate.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 02/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

struct X509
{
    enum CertificateVersion : Int
    {
        case v1 = 0
        case v2 = 1
        case v3 = 2
    }
    
    struct Name
    {
//        Implementations of this specification MUST
//        be prepared to receive the following standard attribute types in
//        issuer and subject (Section 4.1.2.6) names:
//        * country,
//        * organization,
//        * organizational unit,
//        * distinguished name qualifier,
//        * state or province name,
//        * common name (e.g., "Susan Housley"), and
//        * serial number.
//        
//        In addition, implementations of this specification SHOULD be prepared
//        to receive the following standard attribute types in issuer and
//        subject names:
//        
//        * locality,
//        * title,
//        * surname,
//        * given name,
//        * initials,
//        * pseudonym, and
//        * generation qualifier (e.g., "Jr.", "3rd", or "IV").

        var relativeDistinguishedName : [OID:Any]

        init?(asn1sequence : ASN1Sequence)
        {
            var attributes = [OID:Any]()
            for o in asn1sequence.objects {
                guard let set = o as? ASN1Set, set.objects.count == 1 else { return nil  }
                guard let attribute = set.objects[0] as? ASN1Sequence, attribute.objects.count == 2 else { return nil  }
                guard let asn1oid = attribute.objects[0] as? ASN1ObjectIdentifier else { return nil }
                guard let oid = OID(id: asn1oid.identifier) else { return nil }

                let value = attribute.objects[1]
                
                attributes[oid] = value
            }
            
            self.relativeDistinguishedName = attributes
        }
    }
    
    enum Time
    {
        case utcTime(String)            // YYMMDDHHMMSSZ
        case generalizedTime(String)    // YYYYMMDDHHMMSSZ
        
        init?(time : ASN1Time)
        {
            switch time
            {
            case let t as ASN1UTCTime:
                self = .utcTime(t.string)

            case let t as ASN1GeneralizedTime:
                self = .generalizedTime(t.string)
                
            default:
                return nil
            }
        }
    }
    
    struct Validity
    {
        var notBefore   : Time
        var notAfter    : Time
        init?(asn1sequence : ASN1Sequence)
        {
            guard asn1sequence.objects.count == 2 else { return nil }
            guard let asn1NotBefore = asn1sequence.objects[0] as? ASN1Time else { return nil }
            guard let asn1NotAfter  = asn1sequence.objects[1] as? ASN1Time else { return nil }

            guard let notBefore = Time(time: asn1NotBefore) else { return nil }
            guard let notAfter  = Time(time: asn1NotAfter)  else { return nil }
            self.notBefore = notBefore
            self.notAfter  = notAfter
        }
    }
    
    struct BitString
    {
        var numberOfBits    : Int
        var bits            : [UInt8]
        
        init?(bitString: ASN1BitString)
        {
            self.numberOfBits = bitString.value.count * 8 - bitString.unusedBits
            self.bits = bitString.value
        }
    }
    
    struct UniqueIdentifer
    {
        var bitString : BitString
    }
    
    struct AlgorithmIdentifier
    {
        var algorithm   : OID
        var parameters  : Any?

        init?(asn1sequence : ASN1Sequence)
        {
            guard asn1sequence.objects.count >= 1 else { return nil }
            guard let asn1algorithm = asn1sequence.objects[0] as? ASN1ObjectIdentifier else { return nil }
            guard let algorithmOID = OID(id: asn1algorithm.identifier) else { return nil }
            
            self.algorithm = algorithmOID
            
            switch algorithmOID
            {
            case .sha1WithRSAEncryption:
                break
                
            case .sha256WithRSAEncryption:
                break
                
            case .rsaEncryption:
                break
                
            case .ecdsaWithSHA256:
                break

            case .ecPublicKey:
                guard let curveType = asn1sequence.objects[1] as? ASN1ObjectIdentifier else { return nil }
                guard let oid = OID(id: curveType.identifier) else { return nil }
                
                self.parameters = oid
                
                break

            default:
                print("Unsupported signature algorithm \(algorithmOID)")
            }
            
        }
    }
    
    struct SubjectPublicKeyInfo
    {
        var algorithm           : AlgorithmIdentifier
        var subjectPublicKey    : BitString
        init?(asn1sequence : ASN1Sequence)
        {
            guard asn1sequence.objects.count == 2 else { return nil }
            guard let asn1algorithmIdentifier = asn1sequence.objects[0] as? ASN1Sequence else { return nil }
            guard let algorithm = AlgorithmIdentifier(asn1sequence: asn1algorithmIdentifier) else { return nil }
            guard let asn1BitString = asn1sequence.objects[1] as? ASN1BitString else { return nil }
            guard let bitString = BitString(bitString: asn1BitString) else { return nil }
            
            self.algorithm = algorithm
            self.subjectPublicKey = bitString
        }
    }
    
    struct Extension
    {
        var extnID      : OID
        var critical    : Bool
        var extnValue   : [UInt8]
    }
    
    struct TBSCertificate
    {
        var version                 : CertificateVersion
        var serialNumber            : BigInt
        var signature               : AlgorithmIdentifier
        var issuer                  : Name
        var validity                : Validity
        var subject                 : Name
        var subjectPublicKeyInfo    : SubjectPublicKeyInfo
    
        var DEREncodedCertificate   : [UInt8]?
        
        init?(asn1Sequence sequence: ASN1Sequence)
        {
            self.DEREncodedCertificate = sequence.underlyingData
            
            guard sequence.objects.count >= 7 else { return nil }
            
            guard let asn1tbsCertVersion            = (sequence.objects[0] as? ASN1TaggedObject)?.object as? ASN1Integer   else { return nil }
            guard let asn1certificateSerialNumber   = sequence.objects[1] as? ASN1Integer   else { return nil }
            guard let asn1signatureAlgorithm2       = sequence.objects[2] as? ASN1Sequence  else { return nil }
            guard let asn1issuer                    = sequence.objects[3] as? ASN1Sequence  else { return nil }
            guard let asn1validity                  = sequence.objects[4] as? ASN1Sequence  else { return nil }
            guard let asn1subject                   = sequence.objects[5] as? ASN1Sequence  else { return nil }
            guard let asn1subjectPublicKeyInfo      = sequence.objects[6] as? ASN1Sequence  else { return nil }
            
            guard asn1tbsCertVersion.value.count == 1, let version = CertificateVersion(rawValue:Int(asn1tbsCertVersion.value[0])) else { return nil }
            self.version = version
            self.serialNumber = BigInt(bigEndianParts: asn1certificateSerialNumber.value)
            
            guard let signature = AlgorithmIdentifier(asn1sequence: asn1signatureAlgorithm2) else { return nil }
            self.signature = signature
            
            guard let issuer = Name(asn1sequence: asn1issuer) else { return nil }
            self.issuer = issuer
            
            guard let validity = Validity(asn1sequence: asn1validity) else { return  nil }
            self.validity = validity
            
            guard let subject = Name(asn1sequence: asn1subject) else { return nil }
            self.subject = subject

            guard let subjectPublicKeyInfo = SubjectPublicKeyInfo(asn1sequence: asn1subjectPublicKeyInfo) else { return nil }
            self.subjectPublicKeyInfo = subjectPublicKeyInfo
        }
    }
    
    struct Certificate
    {
        var tbsCertificate      : TBSCertificate
        var signatureAlgorithm  : AlgorithmIdentifier
        var signatureValue      : BitString
        
        let data: [UInt8]
        
        var rsa: RSA? {
            let publicKeyInfo = tbsCertificate.subjectPublicKeyInfo
            return RSA(publicKey: publicKeyInfo.subjectPublicKey.bits)
        }
        
        var publicKeySigner: Signing? {
            return self.rsa
        }
        
        var commonName: String? {
            return self.tbsCertificate.subject.relativeDistinguishedName[.commonName] as? String
        }
        
        init?(derData : [UInt8])
        {
            self.data = derData
            
            guard let certificate = ASN1Parser(data:derData).parseObject() as? ASN1Sequence else { return nil }
            guard certificate.objects.count == 3 else { return nil }
            
            guard let asn1tbsCertificate        = certificate.objects[0] as? ASN1Sequence  else { return nil }
            guard let asn1signatureAlgorithm    = certificate.objects[1] as? ASN1Sequence  else { return nil }
            guard let asn1signature             = certificate.objects[2] as? ASN1BitString else { return nil }
            
            guard let tbsCertificate = TBSCertificate(asn1Sequence: asn1tbsCertificate) else { return nil }
            guard let signatureAlgorithm = AlgorithmIdentifier(asn1sequence: asn1signatureAlgorithm) else { return nil }
            guard let signature = BitString(bitString: asn1signature) else { return nil }
            
            self.tbsCertificate = tbsCertificate
            self.signatureAlgorithm = signatureAlgorithm
            self.signatureValue = signature
        }
    
        init?(derData : Data) {
            self.init(derData: derData.UInt8Array())
        }
    }
}
