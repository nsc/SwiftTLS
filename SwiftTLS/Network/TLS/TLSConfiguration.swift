//
//  TLSConfiguration.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public struct TLSConfiguration
{
    var protocolVersion: TLSProtocolVersion
    var minimumFallbackVersion: TLSProtocolVersion
    var cipherSuites: [CipherSuite]

    var dhParameters: DiffieHellmanParameters?
    var ecdhParameters: ECDiffieHellmanParameters?
    
    var hashAlgorithm: HashAlgorithm
    var signatureAlgorithm: SignatureAlgorithm
    
    var identity: Identity?
    
    init(protocolVersion: TLSProtocolVersion, minimumVersion: TLSProtocolVersion? = nil, identity: Identity? = nil)
    {
        self.protocolVersion = protocolVersion
        if let minimumVersion = minimumVersion {
            self.minimumFallbackVersion = minimumVersion
        }
        else {
            self.minimumFallbackVersion = protocolVersion
        }
        self.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.hashAlgorithm = .sha256
        self.signatureAlgorithm = .rsa
        self.identity = identity
    }
}
