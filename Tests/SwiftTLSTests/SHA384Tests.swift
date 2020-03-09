//
//  SHA384.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 16.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest

@testable import SwiftTLS

class SHA384Tests: XCTestCase {
    static var allTests = [
        ("test_sha384_withOneBlockMessage_givesCorrectDigest", test_sha384_withOneBlockMessage_givesCorrectDigest),
        ("test_sha384_withMultiBlockMessage_givesCorrectDigest", test_sha384_withMultiBlockMessage_givesCorrectDigest),
        ("test_sha384_withLongMessage_givesCorrectDigest", test_sha384_withLongMessage_givesCorrectDigest),
    ]

    func test_sha384_withOneBlockMessage_givesCorrectDigest() {
        let sha = SHA384()
        sha.update([UInt8]("abc".utf8))
        let digest = sha.finalize()
        
        let expectedDigest = BigInt("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", radix: 16)!.asBigEndianData()
        
        XCTAssert(digest == expectedDigest)
    }
    
    func test_sha384_withMultiBlockMessage_givesCorrectDigest() {
        let digest = SHA384.hash([UInt8]("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))
        
        let expectedDigest = BigInt("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b", radix: 16)!.asBigEndianData()
        
        XCTAssert(digest == expectedDigest)
    }
    
    func test_sha384_withLongMessage_givesCorrectDigest() {
        let message = [UInt8](repeating: [UInt8]("a".utf8)[0], count: 1_000_000)
        let digest = SHA384.hash(message)
        
        let expectedDigest = BigInt("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985", radix: 16)!.asBigEndianData()
        
        XCTAssert(digest == expectedDigest)
    }
    
}
