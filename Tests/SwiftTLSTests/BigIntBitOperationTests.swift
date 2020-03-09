//
//  BigIntBitOperationTests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 24.07.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class BigIntBitOperationTests: XCTestCase {
    static var allTests = [
        ("test_shiftRight_multiplesOfWordSize_givesCorrectResult", test_shiftRight_multiplesOfWordSize_givesCorrectResult),
        ("test_shiftRight_nonMultiplesOfWordSize_givesCorrectResult", test_shiftRight_nonMultiplesOfWordSize_givesCorrectResult),
        ("test_shiftLeft_multiplesOfWordSize_givesCorrectResult", test_shiftLeft_multiplesOfWordSize_givesCorrectResult),
        ("test_shiftLeft_nonMultiplesOfWordSize_givesCorrectResult", test_shiftLeft_nonMultiplesOfWordSize_givesCorrectResult),
        ]
    
    
    func test_shiftRight_multiplesOfWordSize_givesCorrectResult() {
        let value = BigInt([0x123456789abcdef0, 0xfedcba9876543210, 0xf67819356ef46abc] as [UInt64])
        
        let testVectors = [(64, BigInt([0xfedcba9876543210, 0xf67819356ef46abc] as [UInt64])),
                           (128, BigInt([0xf67819356ef46abc] as [UInt64])),
                           (192, BigInt([0] as [UInt64])),
                           ]
        
        for (shift, result) in testVectors {
            var b = value
            b >>= shift
        
            XCTAssertTrue(b == result)
        }
    }

    func test_shiftRight_nonMultiplesOfWordSize_givesCorrectResult() {
        let value = BigInt("123456789abcdef0fedcba9876543210f67819356ef46abc", radix: 16)!
        
        let testVectors = [(23, BigInt("2468acf13579bde1fdb97530eca86421ecf0326add", radix: 16)!),
                           (85, BigInt("91a2b3c4d5e6f787f6e5d4c3b2", radix: 16)!),
                           (132, BigInt("123456789abcdef", radix: 16)!)
        ]
        
        for (shift, result) in testVectors {
            var b = value
            b >>= shift
            
            XCTAssertTrue(b == result)
        }
    }
    
    func test_shiftLeft_multiplesOfWordSize_givesCorrectResult() {
        let value = BigInt([0x123456789abcdef0, 0xfedcba9876543210, 0xf67819356ef46abc] as [UInt64])
        
        let testVectors = [(64, BigInt([0, 0x123456789abcdef0, 0xfedcba9876543210, 0xf67819356ef46abc] as [UInt64])),
                           (128, BigInt([0, 0, 0x123456789abcdef0, 0xfedcba9876543210, 0xf67819356ef46abc] as [UInt64])),
                           (192, BigInt([0, 0, 0, 0x123456789abcdef0, 0xfedcba9876543210, 0xf67819356ef46abc] as [UInt64])),
                           ]
        
        for (shift, result) in testVectors {
            var b = value
            b <<= shift
            
            XCTAssertTrue(b == result)
        }
    }
    
    func test_shiftLeft_nonMultiplesOfWordSize_givesCorrectResult() {
        let value = BigInt("123456789abcdef0fedcba9876543210f67819356ef46abc", radix: 16)!
        
        let testVectors = [(23, BigInt("91a2b3c4d5e6f787f6e5d4c3b2a19087b3c0c9ab77a355e000000", radix: 16)!),
                           (85, BigInt("2468acf13579bde1fdb97530eca86421ecf0326adde8d578000000000000000000000", radix: 16)!)
        ]
        
        for (shift, result) in testVectors {
            var b = value
            b <<= shift
            
            XCTAssertTrue(b == result)
        }
    }
    
    func test_isBitSet__givesCorrectResult() {
        let value = BigInt("123456789abcdef0fedcba9876543210f67819356ef46abc", radix: 16)!

        for i in 0..<value.bitWidth {
            let a = value >> i
            
            let result = ((a.words.first ?? 0) & 0x1) != 0
            
            let isBitSet = value.isBitSet(i)
            
            XCTAssert(result == isBitSet)
        }
    }
}
