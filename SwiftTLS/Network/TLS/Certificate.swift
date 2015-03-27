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
            var data = SecCertificateCopyData(self.certificate).takeRetainedValue() as NSData
            var buffer = [UInt8](count: data.length, repeatedValue: 0)
            data.getBytes(&buffer, length: data.length)
            
            return buffer
        }
    }
    
    var commonName : String? {
        get {
            var ptr : Unmanaged<CFString>? = nil
            var status = SecCertificateCopyCommonName(certificate, &ptr)
            if status != noErr {
                return nil
            }

            if let commonName = ptr?.takeRetainedValue() {
                return commonName as? String
            }
            
            return nil
        }
    }
    
    var publicKey : CryptoKey? {
        get {
            
            var err : OSStatus = 0
            var publicKeyFromTrust : SecKey? = nil
            
            var ptr : Unmanaged<SecKey>? = nil

            var status = SecCertificateCopyPublicKey(self.certificate, &ptr)
            
            var policy = SecPolicyCreateBasicX509().takeRetainedValue()
            
            var trustPtr : Unmanaged<SecTrust>? = nil
            
            err = SecTrustCreateWithCertificates(self.certificate, policy, &trustPtr)
            assert(err == errSecSuccess)
            
            if let trust = trustPtr?.takeRetainedValue() {
                var trustResult = SecTrustResultType()
                err = SecTrustEvaluate(trust, &trustResult)
                assert(err == errSecSuccess)
                
                if let key = SecTrustCopyPublicKey(trust) {
                    
                    publicKeyFromTrust = key.takeRetainedValue()
                }
            }

            var keyFromCertificate : Unmanaged<SecKey>? = nil
            err = SecCertificateCopyPublicKey(self.certificate, &keyFromCertificate)
            if (err == errSecSuccess) {
                if let k = keyFromCertificate?.takeUnretainedValue() {
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
    
    init?(var certificateData : NSData)
    {
        var unmanagedCert = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData)
        if let cert = unmanagedCert?.takeRetainedValue() {
            self.certificate = cert
        }
        else {
            self.certificate = nil
            return nil
        }
    }

    convenience init?(var certificateData : [UInt8])
    {
        var data = NSData(bytesNoCopy: &certificateData, length: certificateData.count, freeWhenDone: false)
        self.init(certificateData: data)
    }
}