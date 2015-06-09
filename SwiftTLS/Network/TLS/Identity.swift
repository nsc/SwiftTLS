//
//  Identity.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 14.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Security

class Identity
{
    var name : String
    var identity : SecIdentityRef!
    var privateKey  : CryptoKey!
    var certificate : Certificate!
    
    init?(name : String)
    {
        self.name = name
        
        let query : [String:AnyObject] = [
            kSecClass as String     : kSecClassCertificate as String,
            kSecReturnRef as String : kCFBooleanTrue,
            kSecMatchLimit as String : kSecMatchLimitAll,
            kSecAttrLabel as String : name
        ]
        
        var result : Unmanaged<CFTypeRef>? = nil
        let error : OSStatus = SecItemCopyMatching(query, &result)
        
        if (error != noErr) {
            print("Error: could not find identity \(name)")
            return nil
        }
        else {

            if let certificates = result!.takeRetainedValue() as? Array<SecCertificate> {
                
                if certificates.count > 1 {
                    print("Error: more than one certificates are matching \"\(name)\"")
                }
                
                let certificate = certificates[0]
                
                var identity : Unmanaged<SecIdentity>? = nil
                var status = SecIdentityCreateWithCertificate(nil, certificate, &identity)
                
                if status != noErr {
                    print("Error: Could not create identity for certificate matching \(name)")
                    return nil
                }
                
                if let identity = identity?.takeRetainedValue()
                {
                    var privateKey : Unmanaged<SecKey>? = nil
                    status = SecIdentityCopyPrivateKey(identity, &privateKey)
                    
                    if status != noErr {
                        print("Error: Could not get private key for certificate matching \(name)")
                        return nil
                    }
                    
                    if let privateKey = privateKey?.takeRetainedValue()
                    {
                        self.identity = identity
                        self.certificate = Certificate(certificate: certificate)
                        self.privateKey = CryptoKey(key: privateKey)
                        
                        return
                    }
                }
            }
        }
        
        return nil
    }
}