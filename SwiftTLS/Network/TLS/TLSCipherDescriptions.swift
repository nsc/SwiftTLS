//
//  TLSCipherDescriptions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 12.04.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

struct CipherAlgorithmDescriptor {
    var algorithm   : CipherAlgorithm
    var keySize     : Int
    var blockSize   : Int
}

struct CipherSuiteDescriptor {
    var cipherSuite : CipherSuite
    
    var certificateCipherAlgorithm : CertificateCipherAlgorithm
    var bulkCipherAlgorithm : CipherAlgorithmDescriptor
    var cipherType : CipherType
    var blockCipherMode : BlockCipherMode?
    var macAlgorithm : MACAlgorithm
}

let TLSCipherDescritions : [CipherSuite:CipherSuiteDescriptor] = [
    CipherSuite.TLS_RSA_WITH_NULL_MD5: CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_NULL_MD5,
        certificateCipherAlgorithm: .RSA,
        bulkCipherAlgorithm: CipherAlgorithmDescriptor(algorithm: .NULL, keySize: 0, blockSize: 0),
        cipherType: .Stream,
        blockCipherMode: nil,
        macAlgorithm: .HMAC_MD5),
    
    .TLS_RSA_WITH_NULL_SHA: CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_NULL_SHA,
        certificateCipherAlgorithm: .RSA,
        bulkCipherAlgorithm: CipherAlgorithmDescriptor(algorithm: .NULL, keySize: 0, blockSize: 0),
        cipherType: .Stream,
        blockCipherMode: nil,
        macAlgorithm: .HMAC_SHA1),

    .TLS_RSA_WITH_AES_256_CBC_SHA: CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_256_CBC_SHA,
        certificateCipherAlgorithm: .RSA,
        bulkCipherAlgorithm: CipherAlgorithmDescriptor(algorithm: .AES, keySize: kCCKeySizeAES256, blockSize: kCCBlockSizeAES128),
        cipherType: .Stream,
        blockCipherMode: .CBC,
        macAlgorithm: .HMAC_SHA1),

    .TLS_RSA_WITH_AES_256_CBC_SHA256: CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_256_CBC_SHA256,
        certificateCipherAlgorithm: .RSA,
        bulkCipherAlgorithm: CipherAlgorithmDescriptor(algorithm: .AES, keySize: kCCKeySizeAES256, blockSize: kCCBlockSizeAES128),
        cipherType: .Stream,
        blockCipherMode: .CBC,
        macAlgorithm: .HMAC_SHA256),
]
