//
//  TLSServerHelloTests.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftTLS

extension TLSContext {
    convenience init() {
        class EmptyDataProvider : TLSDataProvider
        {
            func writeData(_ data : [UInt8]) throws{}
            func readData(count : Int) throws -> [UInt8] { return []}
        }
        
        self.init(configuration: TLSConfiguration(supportedVersions: [.v1_0]), dataProvider: EmptyDataProvider())
    }
}

class TLSServerHelloTests: XCTestCase {
    
    func test_writeTo__givesCorrectBinaryRepresentation() {
        let random = Random()
        let clientHello = TLSServerHello(
            serverVersion: TLSProtocolVersion.v1_2,
            random: random,
            sessionID: nil,
            cipherSuite: .TLS_RSA_WITH_RC4_128_SHA,
            compressionMethod: .null)
        
        var buffer = DataBuffer()
        clientHello.writeTo(&buffer)
        
        var expectedData = [UInt8]([TLSHandshakeType.serverHello.rawValue, 0, 0, 38, 3, 3])
        var randomData = DataBuffer()
        random.writeTo(&randomData)
        expectedData.append(contentsOf: randomData.buffer)
        expectedData.append(contentsOf: [0, 0, 5, 0])
        XCTAssert(buffer.buffer == expectedData)
    }
    
    var testServerHelloData : [UInt8] {
        get {
            let rc4_md5  = CipherSuite.TLS_RSA_WITH_RC4_128_MD5.rawValue
            let nullCompressionMethod = CompressionMethod.null.rawValue
            
            return [UInt8]([TLSHandshakeType.serverHello.rawValue, 0, 0, 41, 3, 1,
                // random
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                // sessionID
                32,
                1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                // cipher suite
                UInt8((rc4_md5) >> 8), UInt8(rc4_md5 & 0xff),
                // compression method
                nullCompressionMethod])
        }
    }
    
    func test_initWithBinaryInputStream_givesClientHello() {
        let serverHello = TLSServerHello(inputStream: BinaryInputStream(self.testServerHelloData), context:  TLSContext())
        
        XCTAssert(serverHello != nil)
    }
    
    func test_initWithBinaryInputStream_hasCorrectRandom() {
        let serverHello = TLSServerHello(inputStream: BinaryInputStream(self.testServerHelloData), context:  TLSContext())
        
        let expectedRandom = Random(inputStream: BinaryInputStream([UInt8]([1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])))!
        
        let random = serverHello!.random
        
        XCTAssert(random.randomBytes == expectedRandom.randomBytes && random.gmtUnixTime == expectedRandom.gmtUnixTime)
    }
    
    func test_initWithBinaryInputStream_hasCorrectCipherSuites() {
        let serverHello = TLSServerHello(inputStream: BinaryInputStream(self.testServerHelloData), context:  TLSContext())
        
        let expectedCiperSuite = CipherSuite.TLS_RSA_WITH_RC4_128_MD5
        
        XCTAssert(serverHello!.cipherSuite == expectedCiperSuite)
    }
    
}
