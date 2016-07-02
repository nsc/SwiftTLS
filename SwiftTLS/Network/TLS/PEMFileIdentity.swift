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
    var certificate: X509.Certificate
    var rsa: RSA?
    var signer: Signing {
        return _signing
    }
    
    private var _signing: Signing
    
    init?(pemFile: String)
    {
        self.rsa = RSA.fromPEMFile(pemFile)
        _signing = self.rsa!
        
        var certificate: X509.Certificate? = nil
        for (section, object) in ASN1Parser.sectionsFromPEMFile(pemFile) {
            switch section {
            case "CERTIFICATE":
                certificate = X509.Certificate(derData: object.underlyingData!)
            default:
                break
            }
        }
        
        if let cert = certificate {
            self.certificate = cert
        }
        else {
            return nil
        }
    }
}
