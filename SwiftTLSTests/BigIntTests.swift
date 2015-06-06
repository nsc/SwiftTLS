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
        var a = BigInt(1)
        var b = BigInt(2)
        
        var c = a + b
        
        XCTAssert(c == BigInt(3))
    }
    
    func test_subtract_1from2_givesCorrectResult() {
        var a = BigInt(2)
        var b = BigInt(1)
        
        var c = a - b
        
        XCTAssert(c == BigInt(1))
    }

    func test_subtract_2from1_givesCorrectResult() {
        var a = BigInt(1)
        var b = BigInt(2)
        
        var c = a - b
        
        XCTAssert(c == BigInt(-1))
    }

    func test_subtract_with0x10000000000000000And0x1_givesCorrectResult() {
        var a = BigInt([0x0, 0x1] as [UInt64])
        var b = BigInt(1)
        
        var c = a - b
        
        XCTAssertTrue(c == BigInt(0xffffffffffffffff as UInt64))
    }

    func test_subtract_with0x123456789abcdef01And0x123456789abcdef01_givesZero() {
        var a = BigInt([0x23456789abcdef01, 0x1] as [UInt64])
        var b = BigInt([0x23456789abcdef01, 0x1] as [UInt64])
        
        var c = a - b
        
        XCTAssert(c == BigInt(0))
    }

    func test_subtract_someLargNumberfrom0x123_givesCorrectResult() {
        var a = BigInt([0x123] as [UInt32])
        var b = BigInt([0x7de6f837e28f8ede, 0xf7264917def73efd] as [UInt64])
        
        var c = a - b
        
        XCTAssert(c == BigInt([0x7de6f837e28f8dbb, 0xf7264917def73efd] as [UInt64], negative: true))
    }
    
    func test_init_withUInt8Array_givesCorrectResult() {
    
        var a = BigInt([UInt8]([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x21, 0x34]))
        
        XCTAssert(a == BigInt([0x1234, 0x56789abcdef02134] as [UInt64]))
    }
    
    func test_init_withUInt16Array_givesCorrectResult() {
        
        var a = BigInt([UInt16]([0x1234, 0x5678, 0x9abc, 0xdef0, 0x2134]))
        
        XCTAssert(a == BigInt([0x1234, 0x56789abcdef02134] as [UInt64]))
    }

    func test_init_withUInt32Array_givesCorrectResult() {
        
        var a = BigInt([UInt32]([0x1234, 0x56789abc, 0xdef02134]))
        
        XCTAssert(a == BigInt([0x1234, 0x56789abcdef02134] as [UInt64]))
    }

    
}
