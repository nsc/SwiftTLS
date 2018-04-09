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
    
    var supportsSessionResumption = true
    
    // TLS 1.3
    var supportedGroups: [NamedGroup] = [.secp256r1]
    
    enum EarlyDataSupport {
        case notSupported
        case supported(maximumEarlyDataSize: Int)
    }
    
    var earlyData: EarlyDataSupport = .notSupported
    
    init(supportedVersions: [TLSProtocolVersion], identity: Identity? = nil)
    {
        self.supportedVersions = supportedVersions

        self.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        self.hashAlgorithm = .sha256
        self.signatureAlgorithm = .rsa
        self.identity = identity
    }
    
    var minimumSupportedVersion: TLSProtocolVersion {
        var version = supportedVersions.first!
        for v in supportedVersions {
            if version < v {
                version = v
            }
        }
        
        return version
    }

    var maximumSupportedVersion: TLSProtocolVersion {
        var version = supportedVersions.first!
        for v in supportedVersions {
            if version > v {
                version = v
            }
        }
        
        return version
    }

    func supports(_ version: TLSProtocolVersion) -> Bool {
        return self.supportedVersions.contains(version)
    }
    
    func createServerContext() -> TLSServerContext {
        return TLSServerContext()
    }

    func createClientContext() -> TLSClientContext {
        return TLSClientContext()
    }

}
