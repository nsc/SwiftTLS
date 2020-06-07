//
//  TLSConfiguration.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

public struct TLSConfiguration
{
    public init(supportedVersions: [TLSProtocolVersion] = [.v1_3, .v1_2], identity: Identity? = nil)
    {
        self.supportedVersions = supportedVersions
        
        self.hashAlgorithm = .sha256

        self.cipherSuites = TLSConfiguration.cipherSuites(for: supportedVersions)

        self.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)

        guard let identity = identity else {
            return
        }
        
        guard identity.certificateChain.last != nil else {
            fatalError("Identity contains no certificates")
        }
        
        self.identity = identity
        self.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
    }

    public var cipherSuites: [CipherSuite]

    public var dhParameters: DiffieHellmanParameters?
    public var ecdhParameters: ECDiffieHellmanParameters?
    
    var hashAlgorithm: HashAlgorithm
    
    var signatureAlgorithm: SignatureAlgorithm? {
        guard let certificate = identity?.certificateChain.last else {
            return nil
        }
                
        switch certificate.signatureAlgorithm.algorithm {
        case .rsa_pkcs1(hash: _), .rsaEncryption, .rsassa_pss(hash: _, saltLength: _):
            return .rsa
            
        case .ecdsa(hash: _), .ecPublicKey(curveName: _, hash: _):
            return .ecdsa
        }
    }
    
    var identity: Identity?
    
    var supportedVersions: [TLSProtocolVersion]
    
    var supportsSessionResumption = true
    
    var maximumRecordSize: Int? = nil
    
    // TLS 1.3
    public var supportedGroups: [NamedGroup] = [.secp256r1]
    
    public enum EarlyDataSupport {
        case notSupported
        case supported(maximumEarlyDataSize: UInt32)
    }
    
    public var earlyData: EarlyDataSupport = .notSupported
    
    
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
    
    private static func cipherSuites(for supportedVersions: [TLSProtocolVersion]) -> [CipherSuite] {
        var cipherSuites : [CipherSuite] = []
        if supportedVersions.contains(.v1_2) {
            cipherSuites.append(contentsOf: [
                .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//                .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
                ])
        }
        
        if supportedVersions.contains(.v1_3) {
            cipherSuites.append(contentsOf: [
                .TLS_AES_128_GCM_SHA256,
                .TLS_AES_256_GCM_SHA384
                ])
        }
        
        return cipherSuites
    }
}

