//
//  BigIntTests.swift
//  Chat
//
//  Created by Nico Schmidt on 19.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

class BigIntTests: XCTestCase {

    func test_add_withTwoInts_givesCorrectResult() {
        let a = BigInt(1)
        let b = BigInt(2)
        
        let c = a + b
        
        XCTAssert(c == BigInt(3))
    }
    
    func test_subtract_1from2_givesCorrectResult() {
        let a = BigInt(2)
        let b = BigInt(1)
        
        let c = a - b
        
        XCTAssert(c == BigInt(1))
    }

    func test_subtract_2from1_givesCorrectResult() {
        let a = BigInt(1)
        let b = BigInt(2)
        
        let c = a - b
        
        XCTAssert(c == BigInt(-1))
    }

    func test_subtract_with0x10000000000000000And0x1_givesCorrectResult() {
        let a = BigInt([0x0, 0x1] as [UInt64])
        let b = BigInt(1)
        
        let c = a - b
        
        XCTAssertTrue(c == BigInt(0xffffffffffffffff as UInt64))
    }

    func test_subtract_with0x123456789abcdef01And0x123456789abcdef01_givesZero() {
        let a = BigInt([0x23456789abcdef01, 0x1] as [UInt64])
        let b = BigInt([0x23456789abcdef01, 0x1] as [UInt64])
        
        let c = a - b
        
        XCTAssert(c == BigInt(0))
    }

    func test_subtract_someLargNumberfrom0x123_givesCorrectResult() {
        let a = BigInt([0x123] as [UInt32])
        let b = BigInt([0x7de6f837e28f8ede, 0xf7264917def73efd] as [UInt64])
        
        let c = a - b
        
        XCTAssert(c == BigInt([0x7de6f837e28f8dbb, 0xf7264917def73efd] as [UInt64], negative: true))
    }
    
    func test_init_withUInt8Array_givesCorrectResult() {
    
        let a = BigInt([UInt8]([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x21, 0x34]))
        
        XCTAssert(a == BigInt(hexString: "123456789abcdef02134")!)
    }
    
    func test_init_withUInt16Array_givesCorrectResult() {
        
        let a = BigInt([UInt16]([0x1234, 0x5678, 0x9abc, 0xdef0, 0x2134]))
        
        XCTAssert(a == BigInt(hexString: "123456789abcdef02134")!)
    }

    func test_init_withUInt32Array_givesCorrectResult() {
        
        let a = BigInt([UInt32]([0x1234, 0x56789abc, 0xdef02134]))
        
        XCTAssert(a == BigInt(hexString: "123456789abcdef02134")!)
    }

    func test_init_withUInt64Array_givesCorrectResult() {
        
        let a = BigInt([UInt64]([0x1234, 0x56789abcdef02134]))
        
        XCTAssert(a == BigInt(hexString: "123456789abcdef02134")!)
    }

    func test_init_withHexString_givesCorrectResult() {
        
        let a = BigInt(hexString: "1234567890abcdefABCDEF")
        
        XCTAssert(a! == BigInt([0x123456, 0x7890abcdefABCDEF] as [UInt64]))
    }

    func test_init_withSomeHexString_givesCorrectResult() {
        
        let a = BigInt(hexString: "ffffffff12365981274ffffff1231265123ff")
        
        XCTAssert(a! == BigInt([0xfffff, 0xfff12365981274ff, 0xffff1231265123ff] as [UInt64]))
    }

    
    func test_toString__givesCorrectResult()
    {
        let hexString = "1234567890abcdefABCDEF"
        let a = BigInt(hexString: hexString)!
        
        XCTAssert(hexString.lowercaseString == toString(a).lowercaseString)
    }
    
    func BIGNUM_multiply(a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)

        var bn = BN_new()
        BN_hex2bn(&bn, b)

        let context = BN_CTX_new()
        let result = BN_new()
        var r = BN_mul(result, an, bn, context)
        
        return String.fromCString(BN_bn2hex(result))!
    }
    
    func test_multiply_aNumberWithItself_givesCorrectResult()
    {
        let hexString = "123456789abcdef02134"
        let n = BigInt(hexString: hexString)!
        let nSquared = n * n
        
        let s = BIGNUM_multiply(hexString, hexString)
        
        let nString = nSquared.toString()
        
        XCTAssert(nString.lowercaseString == s.lowercaseString)
    }
    
    func test_multiply_twoNumbers_givesCorrectResult()
    {
        let aHex = "ffffffff12365981274ffffff1231265123ff"
        let bHex = "ffffffff26265235ffffff232323f23f23f232323f3243243f"
        let a = BigInt(hexString: aHex)!
        let b = BigInt(hexString: bHex)!
        let product = a * b
        
        let s = BIGNUM_multiply(aHex, bHex)
        
        let productHex = product.toString()
        
        XCTAssert(productHex.lowercaseString == s.lowercaseString)
    }

}
