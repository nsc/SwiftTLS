//
//  TLSCipherDescriptions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 12.04.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import CommonCrypto

struct CipherSuiteDescriptor {
    var cipherSuite : CipherSuite
    
    // TLS 1.3 no longer specifies the key exchange method in the cipher suite,
    // so this is optional (and actually nil for TLS 1.3 cipher suites)
    var keyExchangeAlgorithm : KeyExchangeAlgorithm?

    // TLS 1.3 no longer specifies the certificate type in the cipher suite
    var certificateType : CertificateType?
    
    var bulkCipherAlgorithm : CipherAlgorithm
    var cipherType : CipherType
    var blockCipherMode : BlockCipherMode?
    var fixedIVLength : Int
    var recordIVLength : Int
    var hashFunction: HashAlgorithm
    
    init(cipherSuite: CipherSuite,
         keyExchangeAlgorithm: KeyExchangeAlgorithm? = nil,
         certificateType: CertificateType? = .rsa,
         bulkCipherAlgorithm: CipherAlgorithm,
         cipherType: CipherType,
         blockCipherMode: BlockCipherMode? = nil,
         fixedIVLength: Int = 0,
         recordIVLength: Int = 0,
         hashFunction: HashAlgorithm
    )
    {
        self.cipherSuite = cipherSuite
        self.keyExchangeAlgorithm = keyExchangeAlgorithm
        self.certificateType = certificateType
        self.bulkCipherAlgorithm = bulkCipherAlgorithm
        self.cipherType = cipherType
        self.blockCipherMode = blockCipherMode
        self.fixedIVLength = fixedIVLength
        self.recordIVLength = recordIVLength
        
        if fixedIVLength == 0 {
            self.fixedIVLength = bulkCipherAlgorithm.blockSize
        }

        if recordIVLength == 0 {
            self.recordIVLength = bulkCipherAlgorithm.blockSize
        }

        self.hashFunction = hashFunction
    }
}


let TLSCipherSuiteDescritions : [CipherSuiteDescriptor] = [
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
        cipherSuite: .TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        keyExchangeAlgorithm: .dhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),

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
        hashFunction: .sha256
    ),

    // TLS 1.3 cipher suites
    CipherSuiteDescriptor(
        cipherSuite: .TLS_AES_128_GCM_SHA256,
        certificateType: nil,
        bulkCipherAlgorithm: .aes128,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 4,
        recordIVLength: 8,
        hashFunction: .sha256
    ),

    CipherSuiteDescriptor(
        cipherSuite: .TLS_AES_256_GCM_SHA384,
        certificateType: nil,
        bulkCipherAlgorithm: .aes256,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 4,
        recordIVLength: 8,
        hashFunction: .sha384
    )

]

let TLSCipherSuiteDescriptionDictionary : [CipherSuite:CipherSuiteDescriptor] = {
    var dict = [CipherSuite:CipherSuiteDescriptor]()
    for cipherSuite in TLSCipherSuiteDescritions {
        dict[cipherSuite.cipherSuite] = cipherSuite
    }
    
    return dict
}()
