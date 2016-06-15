//
//  ClientHelloTests.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftTLS

class TLSClientHelloTests: XCTestCase {

    func test_writeTo__givesCorrectBinaryRepresentation() {
        let random = Random()
        let clientHello = TLSClientHello(
            clientVersion: .v1_0,
            random: random,
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_RC4_128_SHA],
            compressionMethods: [.null])
        
        var buffer = DataBuffer()
        clientHello.writeTo(&buffer)
        
        var expectedData = [UInt8]([TLSHandshakeType.clientHello.rawValue, 0, 0, 41, 3, 1])
        var randomData = DataBuffer()
        random.writeTo(&randomData)
        expectedData.append(contentsOf: randomData.buffer)
        expectedData.append(contentsOf: [0, 0, 2, 0, 5, 1, 0])
        XCTAssert(buffer.buffer == expectedData)
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
        let clientHello = TLSClientHello(inputStream: BinaryInputStream(self.testClientHelloData), context:  TLSContext())
        
        XCTAssert(clientHello != nil)
    }

    func test_initWithBinaryInputStream_hasCorrectRandom() {
        let clientHello = TLSClientHello(inputStream: BinaryInputStream(self.testClientHelloData), context:  TLSContext())
        
        let expectedRandom = Random(inputStream: BinaryInputStream([UInt8]([1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])))!
        
        let random = clientHello!.random
        
        XCTAssert(random.randomBytes == expectedRandom.randomBytes && random.gmtUnixTime == expectedRandom.gmtUnixTime)
    }

    func test_initWithBinaryInputStream_hasCorrectCipherSuites() {
        let clientHello = TLSClientHello(inputStream: BinaryInputStream(self.testClientHelloData), context:  TLSContext())
        
        let expectedCiperSuites = [CipherSuite.TLS_RSA_WITH_RC4_128_MD5, CipherSuite.TLS_RSA_WITH_RC4_128_SHA]
        
        XCTAssert(clientHello!.cipherSuites == expectedCiperSuites)
    }
    
    func test_init_withDataWrittenWithWriteTo_resultsInSameAsWeStartedWith()
    {
        let random = Random()
        let clientHello = TLSClientHello(
            clientVersion: .v1_0,
            random: random,
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_RC4_128_SHA],
            compressionMethods: [.null])
        
        clientHello.extensions = [TLSServerNameExtension(serverNames: ["www.example.com", "www.example2.com", "www.example3.com"])]

        var buffer = DataBuffer()
        clientHello.writeTo(&buffer)

        if let newClientHello = TLSClientHello(inputStream: BinaryInputStream(buffer.buffer), context:  TLSContext()) {
            XCTAssertTrue(newClientHello.extensions.count != 0)
            
            let count = clientHello.extensions.count
            XCTAssertTrue(count == newClientHello.extensions.count)
            
            for i in 0..<count
            {
                let e = clientHello.extensions[i]
                let n = newClientHello.extensions[i]
                
                XCTAssertTrue(e as? TLSServerNameExtension != nil)
                XCTAssertTrue(n as? TLSServerNameExtension != nil)
                
                XCTAssertTrue((e as! TLSServerNameExtension).serverNames == (n as! TLSServerNameExtension).serverNames)
            }
        }
        else {
            XCTFail()
        }
    }
    

}
