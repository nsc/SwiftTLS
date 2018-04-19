//
//  GaloisFieldTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13/03/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class GaloisFieldTests: XCTestCase {

    func test_rightshift_works()
    {
        var a = GF2_128_Element(hi: 0xffffffffffffffff, lo: 0xffffffffffffffff)
        
        for i in 0..<128
        {
            a = a.rightshift()
            XCTAssertFalse(a.isBitSet(i))
        }
    }

    func test_leftshift_works()
    {
        var a = GF2_128_Element(hi: 0xffffffffffffffff, lo: 0xffffffffffffffff)
        
        for i in 0..<128
        {
            a = a.leftshift()
            XCTAssertFalse(a.isBitSet(127-i))
        }
    }

}
