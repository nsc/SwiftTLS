//
//  ClientHelloTests.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class TLSClientHelloTests: XCTestCase {
    static var allTests = [
        ("test_writeTo__givesCorrectBinaryRepresentation", test_writeTo__givesCorrectBinaryRepresentation),
        ("test_initWithBinaryInputStream_givesClientHello", test_initWithBinaryInputStream_givesClientHello),
        ("test_initWithBinaryInputStream_hasCorrectRandom", test_initWithBinaryInputStream_hasCorrectRandom),
        ("test_initWithBinaryInputStream_hasCorrectCipherSuites", test_initWithBinaryInputStream_hasCorrectCipherSuites),
        ("test_init_withDataWrittenWithWriteTo_resultsInSameAsWeStartedWith", test_init_withDataWrittenWithWriteTo_resultsInSameAsWeStartedWith),
    ]

    func test_writeTo__givesCorrectBinaryRepresentation() {
        let random = Random()
        let clientHello = TLSClientHello(
            configuration: TLSConfiguration(supportedVersions: [.v1_0]),
            random: random,
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_RC4_128_SHA],
            compressionMethods: [.null])
        
        let context = TLSConnection()
        var buffer = [UInt8]()
        clientHello.writeTo(&buffer, context: context)
        
        var expectedData = [UInt8]([TLSHandshakeType.clientHello.rawValue, 0, 0, 41, 3, 1])
        var randomData = [UInt8]()
        random.writeTo(&randomData, context: context)
        expectedData.append(contentsOf: randomData)
        expectedData.append(contentsOf: [0, 0, 2, 0, 5, 1, 0])
        
        XCTAssert(buffer == expectedData)
    }
    
    var testClientHelloData : [UInt8] {
        get {
            let rc4_md5  = CipherSuite.TLS_RSA_WITH_RC4_128_MD5.rawValue
            let rc4_sha1 = CipherSuite.TLS_RSA_WITH_RC4_128_SHA.rawValue
            
            let (rc4_md5_hi,  rc4_md5_lo)  = (UInt8((rc4_md5)  >> 8), UInt8(rc4_md5  & 0xff))
            let (rc4_sha1_hi, rc4_sha1_lo) = (UInt8((rc4_sha1) >> 8), UInt8(rc4_sha1 & 0xff))
            
            return [UInt8]([TLSHandshakeType.clientHello.rawValue, 0, 0, 41, 3, 1,
                // random
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                // sessionID
                32,
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                // cipher suites
                0, 4, rc4_md5_hi, rc4_md5_lo, rc4_sha1_hi, rc4_sha1_lo,
                // compression methods
                1, 0])
        }
    }
    
    func test_initWithBinaryInputStream_givesClientHello() {
        let clientHello = TLSClientHello(inputStream: BinaryInputStream(self.testClientHelloData), context:  TLSConnection())
        
        XCTAssert(clientHello != nil)
    }

    func test_initWithBinaryInputStream_hasCorrectRandom() {
        let clientHello = TLSClientHello(inputStream: BinaryInputStream(self.testClientHelloData), context:  TLSConnection())
        
        let expectedRandom = Random(inputStream: BinaryInputStream([UInt8]([1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])))!
        
        let random = clientHello!.random
        
        XCTAssert(random.randomBytes == expectedRandom.randomBytes && random.gmtUnixTime == expectedRandom.gmtUnixTime)
    }

    func test_initWithBinaryInputStream_hasCorrectCipherSuites() {
        let clientHello = TLSClientHello(inputStream: BinaryInputStream(self.testClientHelloData), context:  TLSConnection())
        
        let expectedCiperSuites = [CipherSuite.TLS_RSA_WITH_RC4_128_MD5, CipherSuite.TLS_RSA_WITH_RC4_128_SHA]
        
        XCTAssert(clientHello!.cipherSuites == expectedCiperSuites)
    }
    
    func test_init_withDataWrittenWithWriteTo_resultsInSameAsWeStartedWith()
    {
        let random = Random()
        let clientHello = TLSClientHello(
            configuration: TLSConfiguration(supportedVersions: [.v1_0]),
            random: random,
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_RC4_128_SHA],
            compressionMethods: [.null])
        
        clientHello.extensions = [
            TLSServerNameExtension(serverNames: ["www.example.com", "www.example2.com", "www.example3.com"]),
            TLSSecureRenegotiationInfoExtension(renegotiatedConnection: [1,2,3,4])
        ]

        let context = TLSConnection()
        var buffer = [UInt8]()
        clientHello.writeTo(&buffer, context: context)

        if let newClientHello = TLSClientHello(inputStream: BinaryInputStream(buffer), context: context) {
            XCTAssertTrue(newClientHello.extensions.count != 0)
            
            let count = clientHello.extensions.count
            XCTAssertTrue(count == newClientHello.extensions.count)
            
            for i in 0..<count
            {
                let e = clientHello.extensions[i]
                let n = newClientHello.extensions[i]

                let t = type(of: e)
                XCTAssertTrue(t == type(of: n))
                
                switch i {
                case 0:
                    XCTAssertTrue(e is TLSServerNameExtension)
                    XCTAssertTrue((e as! TLSServerNameExtension).serverNames == (n as! TLSServerNameExtension).serverNames)
                    
                case 1:
                    XCTAssertTrue(e is TLSSecureRenegotiationInfoExtension)
                    XCTAssertTrue((e as! TLSSecureRenegotiationInfoExtension).renegotiatedConnection == (n as! TLSSecureRenegotiationInfoExtension).renegotiatedConnection)

                default:
                    XCTFail("Unchecked hello extension")
                }
            }
        }
        else {
            XCTFail()
        }
    }
    

}
