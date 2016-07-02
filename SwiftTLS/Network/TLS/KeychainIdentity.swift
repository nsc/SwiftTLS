//
//  Identity.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 14.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Security

public class KeychainIdentity : Identity
{
    var name: String
    var signer: Signing
    var rsa: RSA?
    
    private var identity: SecIdentity!
    private var privateKey: CryptoKey!
    private var certificate: Certificate!

    public init?(name : String)
    {
        self.name = name
        
        let query : [String:AnyObject] = [
            kSecClass as String     : kSecClassCertificate as String,
            kSecReturnRef as String : kCFBooleanTrue,
            kSecMatchLimit as String : kSecMatchLimitAll,
            kSecAttrLabel as String : name
        ]
        
        var result : CFTypeRef? = nil
        let error : OSStatus = SecItemCopyMatching(query, &result)
        
        if (error != noErr) {
            print("Error: could not find identity \(name)")
            return nil
        }
        else {

            if let certificates = result! as? Array<SecCertificate> {
                
                if certificates.count > 1 {
                    print("Error: more than one certificates are matching \"\(name)\"")
                }
                
                let certificate = certificates[0]
                
                var identity : SecIdentity? = nil
                var status = SecIdentityCreateWithCertificate(nil, certificate, &identity)
                
                if status != noErr {
                    print("Error: Could not create identity for certificate matching \(name)")
                    return nil
                }
                
                if let identity = identity
                {
                    var privateKey : SecKey? = nil
                    status = SecIdentityCopyPrivateKey(identity, &privateKey)
                    
                    if status != noErr {
                        print("Error: Could not get private key for certificate matching \(name)")
                        return nil
                    }
                    
                    if let privateKey = privateKey
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
