//
//  ClientHelloTests.swift
//  Chat
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

class TLSClientHelloTests: XCTestCase {

    func test_writeTo__givesCorrectBinaryRepresentation() {
        var random = Random()
        var clientHello = TLSClientHello(
            clientVersion: TLSProtocolVersion.TLS_v1_0,
            random: random,
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_RC4_128_SHA],
            compressionMethods: [.NULL])
        
        var buffer = DataBuffer()
        clientHello.writeTo(&buffer)
        
        var expectedData = [UInt8]([TLSHandshakeType.ClientHello.rawValue, 0, 0, 41, 3, 1])
        var randomData = DataBuffer()
        random.writeTo(&randomData)
        expectedData.extend(randomData.buffer)
        expectedData.extend([0, 0, 2, 0, 5, 1, 0])
        XCTAssert(buffer.buffer == expectedData)
    }
    
    var testClientHelloData : [UInt8] {
        get {
            var rc4_md5  = CipherSuite.TLS_RSA_WITH_RC4_128_MD5.rawValue
            var rc4_sha1 = CipherSuite.TLS_RSA_WITH_RC4_128_SHA.rawValue
            
            return [UInt8]([TLSHandshakeType.ClientHello.rawValue, 0, 0, 41, 3, 1,
                // random
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                // sessionID
                32,
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                // cipher suites
                0, 4, UInt8((rc4_md5) >> 8), UInt8(rc4_md5 & 0xff), UInt8((rc4_sha1) >> 8), UInt8(rc4_sha1 & 0xff),
                // compression methods
                1, 0])
        }
    }
    
    func test_initWithBinaryInputStream_givesClientHello() {
        var clientHello = TLSClientHello(inputStream: BinaryInputStream(data: self.testClientHelloData))
        
        XCTAssert(clientHello != nil)
    }

    func test_initWithBinaryInputStream_hasCorrectRandom() {
        var clientHello = TLSClientHello(inputStream: BinaryInputStream(data: self.testClientHelloData))
        
        var expectedRandom = Random(inputStream: BinaryInputStream(data: [UInt8]([1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])))!
        
        var random = clientHello!.random
        
        XCTAssert(random.randomBytes == expectedRandom.randomBytes && random.gmtUnixTime == expectedRandom.gmtUnixTime)
    }

    func test_initWithBinaryInputStream_hasCorrectCipherSuites() {
        var clientHello = TLSClientHello(inputStream: BinaryInputStream(data: self.testClientHelloData))
        
        var expectedCiperSuites = [CipherSuite.TLS_RSA_WITH_RC4_128_MD5, CipherSuite.TLS_RSA_WITH_RC4_128_SHA]
        
        XCTAssert(clientHello!.cipherSuites == expectedCiperSuites)
    }

}
