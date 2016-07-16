//
//  PEMFileIdentity.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 02.07.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

class PEMFileIdentity : Identity
{
    var certificateChain: [X509.Certificate]
    var rsa: RSA?
    var signer: Signing {
        return _signing
    }
    
    private var _signing: Signing
    
    init?(certificateFile: String, privateKeyFile: String)
    {
        self.rsa = RSA.fromPEMFile(privateKeyFile)
        _signing = self.rsa!
        
        certificateChain = []
        for (section, object) in ASN1Parser.sectionsFromPEMFile(certificateFile) {
            switch section {
            case "CERTIFICATE":
                if let certificate = X509.Certificate(derData: object.underlyingData!) {
                    certificateChain.append(certificate)
                }
            default:
                break
            }
        }
        
        if certificateChain.count == 0 {
            return nil
        }
    }
    
    convenience init?(pemFile: String)
    {
        self.init(certificateFile: pemFile, privateKeyFile: pemFile)
    }
}
