//
//  MontgomeryTests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 28.07.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest

@testable import SwiftTLS

class MontgomeryTests: XCTestCase {
    static var allTests = [
        ("test_multiply_forSomeInput_givesCorrectResult", test_multiply_forSomeInput_givesCorrectResult),
        ("test_modular_pow_forSomeInput_givesCorrectResult", test_modular_pow_forSomeInput_givesCorrectResult),
    ]
    
    func test_multiply_forSomeInput_givesCorrectResult() {
        let modulus = BigInt(72639)
        let sut = Montgomery(modulus: modulus)
        
        print((sut.r * sut.rInv) % sut.modulus)
        print((sut.modulus * sut.mDash) % sut.r)
        
        let a = BigInt(5791)
        let b = BigInt(1229)
        let aMon = sut.montgomeryReduce(BigInt(5791))
        let bMon = sut.montgomeryReduce(BigInt(1229))
        let result = sut.multiply(aMon, bMon)
        
        XCTAssert((a * b) % modulus == (result * sut.rInv) % modulus)
    }

    func test_modular_pow_forSomeInput_givesCorrectResult() {
        let modulus = BigInt(72639)
        let sut = Montgomery(modulus: modulus)
        
        let a = BigInt(5791)
        let exponent = BigInt(175)
        let result = sut.modular_pow(a, exponent)

        XCTAssert(result == modular_pow(a, exponent, modulus))
    }

}
