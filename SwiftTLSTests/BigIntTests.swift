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
        var a = BigInt([0x0, 0x1])
        var b = BigInt(1)
        
        var c = a - b
        
        XCTAssert(c == BigInt([0xffffffffffffffff]))
    }

    func test_subtract_with0x123456789abcdef01And0x123456789abcdef01_givesZero() {
        var a = BigInt([0x23456789abcdef01, 0x1])
        var b = BigInt([0x23456789abcdef01, 0x1])
        
        var c = a - b
        
        XCTAssert(c == BigInt(0))
    }

    func test_subtract_someLargNumberfrom0x123_givesCorrectResult() {
        var a = BigInt([0x123])
        var b = BigInt([0x7de6f837e28f8ede, 0xf7264917def73efd])
        
        var c = a - b
        
        XCTAssert(c == BigInt([0x7de6f837e28f8dbb, 0xf7264917def73efd], negative: true))
    }
    
}
