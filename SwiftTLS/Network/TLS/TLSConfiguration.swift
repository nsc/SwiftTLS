//
//  TLSConfiguration.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public struct TLSConfiguration
{
    var protocolVersion : TLSProtocolVersion
    var cipherSuites : [CipherSuite]

    var certificatePath : String?
    var dhParameters : DiffieHellmanParameters?
    var ecdhParameters : ECDiffieHellmanParameters?
    
    var hashAlgorithm : HashAlgorithm
    var signatureAlgorithm : SignatureAlgorithm
    
    var identity : Identity?
    
    init(protocolVersion : TLSProtocolVersion)
    {
        self.protocolVersion = protocolVersion
        self.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.hashAlgorithm = .SHA1
        self.signatureAlgorithm = .RSA
    }
}