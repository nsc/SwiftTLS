//
//  PEMFileIdentity.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 02.07.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

public class PEMFileIdentity
{
    public var certificateChain: [X509.Certificate]
    public var signer: Signing {
        return _signing
    }
    
    private var _signing: Signing
    
    public init?(certificateFile: String, privateKeyFile: String)
    {
        if let rsa = RSA.fromPEMFile(privateKeyFile) {
            _signing = rsa
        }
        else if let ecdsa = ECDSA.fromPEMFile(privateKeyFile) {
            _signing = ecdsa
        }
        else {
            return nil
        }
        
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
    
    public convenience init?(pemFile: String)
    {
        self.init(certificateFile: pemFile, privateKeyFile: pemFile)
    }
}

extension PEMFileIdentity : Identity {}
