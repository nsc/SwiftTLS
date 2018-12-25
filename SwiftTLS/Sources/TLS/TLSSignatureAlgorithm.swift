//
//  TLSSignatureAlgorithm.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

public enum TLSSignatureScheme : UInt16 {
    /* RSASSA-PKCS1-v1_5 algorithms */
    case rsa_pkcs1_sha1 = 0x0201
    case rsa_pkcs1_sha256 = 0x0401
    case rsa_pkcs1_sha384 = 0x0501
    case rsa_pkcs1_sha512 = 0x0601
    
    /* ECDSA algorithms */
    case ecdsa_secp256r1_sha256 = 0x0403
    case ecdsa_secp384r1_sha384 = 0x0503
    case ecdsa_secp521r1_sha512 = 0x0603
    
    /* RSASSA-PSS algorithms */
    case rsa_pss_sha256 = 0x0804
    case rsa_pss_sha384 = 0x0805
    case rsa_pss_sha512 = 0x0806
    
    /* EdDSA algorithms */
    case ed25519 = 0x0807
    case ed448 = 0x0808
    
    init?(signatureAlgorithm: X509.SignatureAlgorithm)
    {
        switch (signatureAlgorithm) {
        case .rsa_pkcs1(let hashAlgorithm):
            switch hashAlgorithm {
            case .sha1:
                self = .rsa_pkcs1_sha1

            case .sha256:
                self = .rsa_pkcs1_sha256

            case .sha384:
                self = .rsa_pkcs1_sha384
            
            case .sha512:
                self = .rsa_pkcs1_sha512
                
            default:
                return nil
            }

        case .rsassa_pss(let hashAlgorithm, _):
            switch hashAlgorithm {
            case .sha256:
                self = .rsa_pss_sha256
                
            case .sha384:
                self = .rsa_pss_sha384
                
            case .sha512:
                self = .rsa_pss_sha512
                
            default:
                return nil
            }
            
        case .ecPublicKey(let curveName, let hashAlgorithm):
            switch (curveName, hashAlgorithm) {
            case (.ansip521r1, .sha512):
                self = .ecdsa_secp521r1_sha512

            case (.ansip384r1, .sha384):
                self = .ecdsa_secp384r1_sha384

            case (.prime256v1, .sha256):
                self = .ecdsa_secp256r1_sha256
                
            default:
                log("Unsupported signature scheme \(curveName), \(hashAlgorithm)")
                return nil
            }
        default:
            return nil
        }
    }
    
    var signatureAlgorithm: X509.SignatureAlgorithm? {
        switch self {
        case .ecdsa_secp256r1_sha256:
            return .ecPublicKey(curveName: NamedGroup.secp256r1.oid, hash: .sha256)

        case .ecdsa_secp521r1_sha512:
            return .ecPublicKey(curveName: NamedGroup.secp521r1.oid, hash: .sha512)
            
        case .rsa_pss_sha256:
            return .rsassa_pss(hash: .sha256, saltLength: HashAlgorithm.sha256.hashLength)

        case .rsa_pss_sha384:
            return .rsassa_pss(hash: .sha384, saltLength: HashAlgorithm.sha384.hashLength)

        case .rsa_pss_sha512:
            return .rsassa_pss(hash: .sha512, saltLength: HashAlgorithm.sha512.hashLength)

        case .rsa_pkcs1_sha256:
            return .rsa_pkcs1(hash: .sha256)

        case .rsa_pkcs1_sha384:
            return .rsa_pkcs1(hash: .sha384)

        case .rsa_pkcs1_sha512:
            return .rsa_pkcs1(hash: .sha512)
            
        default:
            log("Unsupported signature algorithm \(self)")
            return nil
        }
    }
    
    var hashAlgorithm: HashAlgorithm? {
        switch self {
        case .rsa_pkcs1_sha1:
            return .sha1
            
        case .rsa_pkcs1_sha256, .ecdsa_secp256r1_sha256, .rsa_pss_sha256:
            return .sha256
            
        case .rsa_pkcs1_sha384, .ecdsa_secp384r1_sha384, .rsa_pss_sha384:
            return .sha384
            
        case .rsa_pkcs1_sha512, .ecdsa_secp521r1_sha512, .rsa_pss_sha512:
            return .sha512
            
        default:
            return nil
        }
    }
    
    var isRSA: Bool {
        switch self {
        case .rsa_pkcs1_sha1, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384,
             .rsa_pkcs1_sha512, .rsa_pss_sha256, .rsa_pss_sha384,
             .rsa_pss_sha512:
            return true
        
        default:
            return false
        }
    }

    var isECDSA: Bool {
        switch self {
        case .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384,
             .ecdsa_secp521r1_sha512:
            return true
            
        default:
            return false
        }
    }

    var isEdDSA: Bool {
        switch self {
        case .ed25519, .ed448:
            return true
            
        default:
            return false
        }
    }

}
