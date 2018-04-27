//
//  SHA224Tests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 16.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class SHA224Tests: XCTestCase {
    static var allTests = [
        ("test_sha224_withOneBlockMessage_givesCorrectDigest", test_sha224_withOneBlockMessage_givesCorrectDigest),
        ("test_sha224_withMultiBlockMessage_givesCorrectDigest", test_sha224_withMultiBlockMessage_givesCorrectDigest),
        ("test_sha224_withLongMessage_givesCorrectDigest", test_sha224_withLongMessage_givesCorrectDigest),
    ]

    func test_sha224_withOneBlockMessage_givesCorrectDigest() {
        let sha = SHA224()
        sha.update([UInt8]("abc".utf8))
        let digest = sha.finalize()
        
        XCTAssert(digest == [0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7])
    }
    
    func test_sha224_withMultiBlockMessage_givesCorrectDigest() {
        let digest = SHA224.hash([UInt8]("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))
        
        let expectedDigest: [UInt8] = [0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25]
        
        XCTAssert(digest == expectedDigest)
    }
    
    func test_sha224_withLongMessage_givesCorrectDigest() {
        let message = [UInt8](repeating: [UInt8]("a".utf8)[0], count: 1_000_000)
        let digest = SHA224.hash(message)
        
        XCTAssert(digest == [0x20, 0x79, 0x46, 0x55, 0x98, 0x0c, 0x91, 0xd8, 0xbb, 0xb4, 0xc1, 0xea, 0x97, 0x61, 0x8a, 0x4b, 0xf0, 0x3f, 0x42, 0x58, 0x19, 0x48, 0xb2, 0xee, 0x4e, 0xe7, 0xad, 0x67])
    }
    
}
