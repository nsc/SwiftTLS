//
//  Certificate.swift
//
//  Created by Nico Schmidt on 17.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class KeychainCertificate
{
    private var certificate : SecCertificate!
    private var certificateData : [UInt8]
    
    private lazy var asn1certificate : ASN1Sequence? = {
        return ASN1Parser(data: self.certificateData).parseObject() as? ASN1Sequence
    }()
    
    var data : [UInt8] {
        get {
            let data = SecCertificateCopyData(self.certificate) as Data
            var buffer = [UInt8](repeating: 0, count: data.count)
            (data as NSData).getBytes(&buffer, length: data.count)
            
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
                var trustResult = SecTrustResultType.unspecified
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
                guard let subSequence = object as? ASN1Sequence, subSequence.objects.count == 2 else { continue }
                guard let oidSequence = subSequence.objects[0] as? ASN1Sequence, oidSequence.objects.count == 2 else { continue }
                guard let oidObject = oidSequence.objects.first as? ASN1ObjectIdentifier else { continue }
                guard let oid = OID(id: oidObject.identifier) else { continue }
                
                guard oid == OID.rsaEncryption else { continue }
                if let bitString = subSequence.objects[1] as? ASN1BitString {
                    return RSA(publicKey: bitString.value)
                }
            }
            
            return nil
        }
    }
    
    init(certificate : SecCertificate)   {
        let data = SecCertificateCopyData(certificate) as Data
        var array = [UInt8](repeating: 0, count: data.count)
        array.withUnsafeMutableBufferPointer { memcpy($0.baseAddress, (data as NSData).bytes, data.count); return }
        
        self.certificateData = array
        self.certificate = certificate
    }
    
    init?(certificateData : Data)
    {
        let unmanagedCert = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData)
        guard let cert = unmanagedCert else { return nil }
        
        self.certificate = cert
        var array = [UInt8](repeating: 0, count: certificateData.count)
        array.withUnsafeMutableBufferPointer { memcpy($0.baseAddress, (certificateData as NSData).bytes, certificateData.count); return }
        self.certificateData = array
    }

    convenience init?(certificateData : [UInt8])
    {
//        if let object = ASN1Parser(data: certificateData).parseObject()
//        {
//            ASN1_printObject(object)
//        }

        var certificateData = certificateData
        let data = Data(bytesNoCopy: &certificateData, count: certificateData.count, deallocator: .none)
        self.init(certificateData: data)
    }
}
