//
//  TLSConfiguration.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public struct TLSConfiguration
{
    var cipherSuites: [CipherSuite]

    var dhParameters: DiffieHellmanParameters?
    var ecdhParameters: ECDiffieHellmanParameters?
    
    var hashAlgorithm: HashAlgorithm
    var signatureAlgorithm: SignatureAlgorithm
    
    var identity: Identity?
    
    var supportedVersions: [TLSProtocolVersion]
    
    // TLS 1.3
    var supportedGroups: [NamedGroup]? = [.secp256r1]
    
    init(supportedVersions: [TLSProtocolVersion], identity: Identity? = nil)
    {
        self.supportedVersions = supportedVersions

        self.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.hashAlgorithm = .sha256
        self.signatureAlgorithm = .rsa
        self.identity = identity
    }
    
    func supports(_ version: TLSProtocolVersion) -> Bool {
        return self.supportedVersions.contains(version)
    }
}
