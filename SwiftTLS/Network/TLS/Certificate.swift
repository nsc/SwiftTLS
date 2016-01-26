//
//  Certificate.swift
//  Chat
//
//  Created by Nico Schmidt on 17.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class Certificate
{
    private var certificate : SecCertificateRef!
    private var certificateData : [UInt8]
    
    private lazy var asn1certificate : ASN1Sequence? = {
        return ASN1Parser(data: self.certificateData).parseObject() as? ASN1Sequence
    }()
    
    var data : [UInt8] {
        get {
            let data = SecCertificateCopyData(self.certificate) as NSData
            var buffer = [UInt8](count: data.length, repeatedValue: 0)
            data.getBytes(&buffer, length: data.length)
            
            return buffer
        }
    }
    
    var commonName : String? {
        get {
            var ptr : CFString? = nil
            let status = SecCertificateCopyCommonName(certificate, &ptr)
            if status != noErr {
                return nil
            }

            if let commonName = ptr {
                return commonName as String
            }
            
            return nil
        }
    }
    
    var publicKey : CryptoKey? {
        get {
            
            var err : OSStatus = 0
            var publicKeyFromTrust : SecKey?
            
            let policy = SecPolicyCreateBasicX509()
            
            var trustPtr : SecTrust? = nil
            
            err = SecTrustCreateWithCertificates(self.certificate, policy, &trustPtr)
            assert(err == errSecSuccess)
            
            if let trust = trustPtr {
                var trustResult = SecTrustResultType()
                err = SecTrustEvaluate(trust, &trustResult)
                assert(err == errSecSuccess)
                
                if let key = SecTrustCopyPublicKey(trust) {
                    
                    publicKeyFromTrust = key
                }
            }

            var keyFromCertificate : SecKey? = nil
            err = SecCertificateCopyPublicKey(self.certificate, &keyFromCertificate)
            if (err == errSecSuccess) {
                if let k = keyFromCertificate {
                    return CryptoKey(key: k)
                }
            }
            
            return nil
        }
    }
    
    var publicKeySigner : Signing? {
        get {
            guard let sequence = self.asn1certificate else {
                return nil
            }
            
            guard let firstSequence = sequence.objects.first as? ASN1Sequence else {
                return nil
            }
            
            for object in firstSequence.objects
            {
                guard let subSequence = object as? ASN1Sequence where subSequence.objects.count == 2 else { continue }
                guard let oidSequence = subSequence.objects[0] as? ASN1Sequence where oidSequence.objects.count == 2 else { continue }
                guard let oidObject = oidSequence.objects.first as? ASN1ObjectIdentifier else { continue }
                guard let oid = OID(id: oidObject.identifier) else { continue }
                
                guard oid == OID.RSAEncryption else { continue }
                if let bitString = subSequence.objects[1] as? ASN1BitString {
                    return RSA(publicKey: bitString.value)
                }
            }
            
            return nil
        }
    }
    
    init(certificate : SecCertificateRef)
    {
        let data = SecCertificateCopyData(certificate) as NSData
        var array = [UInt8](count:data.length, repeatedValue: 0)
        array.withUnsafeMutableBufferPointer { memcpy($0.baseAddress, data.bytes, data.length); return }
        
        self.certificateData = array
        self.certificate = certificate
    }
    
    init?(certificateData : NSData)
    {
        let unmanagedCert = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData)
        if let cert = unmanagedCert {
            self.certificate = cert
            var array = [UInt8](count:certificateData.length, repeatedValue: 0)
            array.withUnsafeMutableBufferPointer { memcpy($0.baseAddress, certificateData.bytes, certificateData.length); return }
            self.certificateData = array
        }
        else {
            self.certificate = nil
            self.certificateData = []
            return nil
        }
    }

    convenience init?(var certificateData : [UInt8])
    {
        if let object = ASN1Parser(data: certificateData).parseObject()
        {
            ASN1_printObject(object)
        }

        let data = NSData(bytesNoCopy: &certificateData, length: certificateData.count, freeWhenDone: false)
        self.init(certificateData: data)
    }
}