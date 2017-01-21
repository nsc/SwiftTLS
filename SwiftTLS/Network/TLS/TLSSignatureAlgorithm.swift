//
//  TLSSignatureAlgorithm.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

public enum TLSSignatureAlgorithm : UInt16 {
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
}
