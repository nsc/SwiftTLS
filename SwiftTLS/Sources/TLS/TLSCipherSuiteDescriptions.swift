//
//  TLSCipherDescriptions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 12.04.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public struct CipherSuiteDescriptor {
    public let cipherSuite : CipherSuite
    
    // TLS 1.3 no longer specifies the key exchange method in the cipher suite,
    // so this is optional (and actually nil for TLS 1.3 cipher suites)
    public let keyExchangeAlgorithm : KeyExchangeAlgorithm?

    // TLS 1.3 no longer specifies the certificate type in the cipher suite
    public let certificateType : CertificateType?
    
    public let bulkCipherAlgorithm : CipherAlgorithm
    public let cipherType : CipherType
    public let blockCipherMode : BlockCipherMode?
    public let fixedIVLength : Int
    public let recordIVLength : Int
    public let authTagSize : Int // only for AEAD
    public let hashAlgorithm: HashAlgorithm
    
    public let supportedProtocolVersions: [TLSProtocolVersion]
    
    init(cipherSuite: CipherSuite,
         keyExchangeAlgorithm: KeyExchangeAlgorithm? = nil,
         certificateType: CertificateType? = .rsa,
         bulkCipherAlgorithm: CipherAlgorithm,
         cipherType: CipherType,
         blockCipherMode: BlockCipherMode? = nil,
         fixedIVLength: Int = 0,
         recordIVLength: Int = 0,
         authTagSize: Int = 0,
         hashFunction: HashAlgorithm,
         supportedProtocolVersions: [TLSProtocolVersion] = [.v1_2]
    )
    {
        self.cipherSuite = cipherSuite
        self.keyExchangeAlgorithm = keyExchangeAlgorithm
        self.certificateType = certificateType
        self.bulkCipherAlgorithm = bulkCipherAlgorithm
        self.cipherType = cipherType
        self.blockCipherMode = blockCipherMode
        self.fixedIVLength = fixedIVLength != 0 ? fixedIVLength : bulkCipherAlgorithm.blockSize
        self.recordIVLength = recordIVLength != 0 ? recordIVLength : bulkCipherAlgorithm.blockSize
        self.authTagSize = authTagSize
        
        self.hashAlgorithm = hashFunction
        self.supportedProtocolVersions = supportedProtocolVersions
    }
}


let TLSCipherSuiteDescriptions : [CipherSuiteDescriptor] = [
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_NULL_MD5,
        keyExchangeAlgorithm: .rsa,
        bulkCipherAlgorithm: .null,
        cipherType: .stream,
        hashFunction: .md5
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_NULL_SHA,
        keyExchangeAlgorithm: .rsa,
        bulkCipherAlgorithm: .null,
        cipherType: .stream,
        hashFunction: .sha1
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_256_CBC_SHA,
        keyExchangeAlgorithm: .rsa,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_128_CBC_SHA256,
        keyExchangeAlgorithm: .rsa,
        bulkCipherAlgorithm: .aes128,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_256_CBC_SHA256,
        keyExchangeAlgorithm: .rsa,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        keyExchangeAlgorithm: .dhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        keyExchangeAlgorithm: .dhe,
        bulkCipherAlgorithm: .aes128,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        keyExchangeAlgorithm: .dhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),

//    CipherSuiteDescriptor(
//        cipherSuite: .TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
//        keyExchangeAlgorithm: .dhe,
//        bulkCipherAlgorithm: .aes256,
//        cipherType: .block,
//        blockCipherMode: .gcm,
//        hashFunction: .sha384
//    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_NULL_MD5,
        keyExchangeAlgorithm: .rsa,
        bulkCipherAlgorithm: .null,
        cipherType: .stream,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes128,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha384
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes128,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes128,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 4,
        recordIVLength: 8,
        authTagSize: 16,
        hashFunction: .sha256
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 4,
        recordIVLength: 8,
        authTagSize: 16,
        hashFunction: .sha384
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        keyExchangeAlgorithm: .ecdhe,
        certificateType: .ecdsa,
        bulkCipherAlgorithm: .aes128,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 4,
        recordIVLength: 8,
        authTagSize: 16,
        hashFunction: .sha256
    ),

    // TLS 1.3 cipher suites
    CipherSuiteDescriptor(
        cipherSuite: .TLS_AES_128_GCM_SHA256,
        certificateType: nil,
        bulkCipherAlgorithm: .aes128,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 12,
        authTagSize: 16,
        hashFunction: .sha256,
        supportedProtocolVersions: [.v1_3]
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_AES_256_GCM_SHA384,
        certificateType: nil,
        bulkCipherAlgorithm: .aes256,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 12,
        authTagSize: 16,
        hashFunction: .sha384,
        supportedProtocolVersions: [.v1_3]
    )

]

let TLSCipherSuiteDescriptionDictionary : [CipherSuite:CipherSuiteDescriptor] = {
    var dict = [CipherSuite:CipherSuiteDescriptor]()
    for cipherSuite in TLSCipherSuiteDescriptions {
        dict[cipherSuite.cipherSuite] = cipherSuite
    }
    
    return dict
}()
