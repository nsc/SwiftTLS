//
//  SHA512Tests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 16.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class SHA512Tests: XCTestCase {
    static var allTests = [
        ("test_sha512_withOneBlockMessage_givesCorrectDigest", test_sha512_withOneBlockMessage_givesCorrectDigest),
        ("test_sha512_withMultiBlockMessage_givesCorrectDigest", test_sha512_withMultiBlockMessage_givesCorrectDigest),
        ("test_sha512_withLongMessage_givesCorrectDigest", test_sha512_withLongMessage_givesCorrectDigest),
    ]
    
    func test_sha512_withOneBlockMessage_givesCorrectDigest() {
        let sha = SHA512()
        sha.update([UInt8]("abc".utf8))
        let digest = sha.finalize()
        
        let expectedDigest = BigInt(hexString: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")!.asBigEndianData()

        XCTAssert(digest == expectedDigest)
    }
    
    func test_sha512_withMultiBlockMessage_givesCorrectDigest() {
        let digest = SHA512.hash([UInt8]("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))
        
        let expectedDigest = BigInt(hexString: "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")!.asBigEndianData()
        
        XCTAssert(digest == expectedDigest)
    }
    
    func test_sha512_withLongMessage_givesCorrectDigest() {
        let message = [UInt8](repeating: [UInt8]("a".utf8)[0], count: 1_000_000)
        let digest = SHA512.hash(message)
        
        let expectedDigest = BigInt(hexString: "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")!.asBigEndianData()
        
        XCTAssert(digest == expectedDigest)
    }
    
}
