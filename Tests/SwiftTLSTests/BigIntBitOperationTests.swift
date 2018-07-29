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
        let value = BigInt(hexString: "123456789abcdef0fedcba9876543210f67819356ef46abc")!
        
        let testVectors = [(23, BigInt(hexString: "2468acf13579bde1fdb97530eca86421ecf0326add")!),
                            (85, BigInt(hexString: "91a2b3c4d5e6f787f6e5d4c3b2")!)
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
        let value = BigInt(hexString: "123456789abcdef0fedcba9876543210f67819356ef46abc")!
        
        let testVectors = [(23, BigInt(hexString: "91a2b3c4d5e6f787f6e5d4c3b2a19087b3c0c9ab77a355e000000")!),
                           (85, BigInt(hexString: "2468acf13579bde1fdb97530eca86421ecf0326adde8d578000000000000000000000")!)
        ]
        
        for (shift, result) in testVectors {
            var b = value
            b <<= shift
            
            XCTAssertTrue(b == result)
        }
    }

}
