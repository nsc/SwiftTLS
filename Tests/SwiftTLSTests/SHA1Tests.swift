//
//  SHA1Tests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 16.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class SHA1Tests: XCTestCase {
    static var allTests = [
        ("test_sha1_withOneBlockMessage_givesCorrectDigest", test_sha1_withOneBlockMessage_givesCorrectDigest),
        ("test_sha1_withMultiBlockMessage_givesCorrectDigest", test_sha1_withMultiBlockMessage_givesCorrectDigest),
        ("test_sha1_withLongMessage_givesCorrectDigest", test_sha1_withLongMessage_givesCorrectDigest),
    ]

    func test_sha1_withOneBlockMessage_givesCorrectDigest() {
        let sha1 = SHA1()
        sha1.update([UInt8]("abc".utf8))
        let digest = sha1.finalize()
        
        XCTAssert(digest == [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d])
    }
    
    func test_sha1_withMultiBlockMessage_givesCorrectDigest() {
        let digest = SHA1.hash([UInt8]("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))
        
        XCTAssert(digest == [0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1])
    }
    
    func test_sha1_withLongMessage_givesCorrectDigest() {
        let message = [UInt8](repeating: [UInt8]("a".utf8)[0], count: 1_000_000)
        let digest = SHA1.hash(message)
        
        XCTAssert(digest == [0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f])
    }
    
}
