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
            
            var ptr : SecKey? = nil

            SecCertificateCopyPublicKey(self.certificate, &ptr)
            
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
    
    init(certificate : SecCertificateRef)
    {
        self.certificate = certificate
    }
    
    init?(certificateData : NSData)
    {
        let unmanagedCert = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData)
        if let cert = unmanagedCert {
            self.certificate = cert
        }
        else {
            self.certificate = nil
            return nil
        }
    }

    convenience init?(var certificateData : [UInt8])
    {
        let data = NSData(bytesNoCopy: &certificateData, length: certificateData.count, freeWhenDone: false)
        self.init(certificateData: data)
    }
}