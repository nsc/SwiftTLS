//
//  BigIntTests.swift
//
//  Created by Nico Schmidt on 19.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
import OpenSSL
import SwiftHelper
@testable import SwiftTLS

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

    func test_subtract_negative2from1_givesCorrectResult() {
        let a = BigInt(1)
        let b = BigInt(-2)
        
        let c = a - b
        
        XCTAssert(c == BigInt(3))
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
    
    func test_subtract()
    {
        let abValues : [([UInt8], [UInt8])] = [
            ([248, 197, 122, 25, 35, 101, 23, 247, 212, 141, 27, 187, 109], [148, 70, 148, 108, 221, 70, 154, 29, 242, 127, 187, 109]),
        ([247, 107, 148, 172, 81, 75, 136, 52, 61, 240, 165, 216, 64, 195, 160, 76, 212, 136, 242, 108, 227, 114, 77], [136, 60, 228, 253, 68, 33, 223, 190, 37, 174, 127, 153, 17, 116, 88, 225, 177, 222, 127, 122, 68, 23, 77])
        ]
        
        for (aa, bb) in abValues
        {
            let a = BigInt(aa)
            let b = BigInt(bb)
            let c = a - b
            
            let d = c + b
            
            XCTAssert(a == d, "Wrong result for \(a) - \(b)")
        }
    }
    
    func test_multiply_negativeAndAPositiveNumbers_givesCorrectResult()
    {
        let values = [
            (3, -4, -12),
            (-3, 4, -12),
            (-3, -4, 12),
            (3, 4, 12),
        ]
        
        for (a, b, result) in values {
        
            let r = BigInt(a) * BigInt(b)

            XCTAssert(BigInt(result) == r)
        }
    }
    
    func test_lessThan__givesCorrectResult()
    {
        let abValues : [([UInt8], [UInt8], Bool)] = [
            ([37, 46, 7, 91, 243, 78], [224, 96, 49, 120, 243, 78], true),
            ([224, 96, 49, 120, 243, 78], [37, 46, 7, 91, 243, 78], false),
            ([37, 46, 7, 91, 243], [224, 96, 49, 120, 243, 78], true),
            ([1, 2, 3], [1, 2], false),
            ([224, 96, 49, 120, 243, 78], [224, 96, 49, 120, 243, 78], false),
        ]
        
        for (aa, bb, result) in abValues
        {
            let a = BigInt(aa)
            let b = BigInt(bb)
            let lessThan = a < b
            
            XCTAssert(lessThan == result, "Wrong result for \(a) < \(b)")
        }
    }
    
    func test_greaterThan__givesCorrectResult()
    {
        let abValues : [([UInt8], [UInt8], Bool)] = [
            ([37, 46, 7, 91, 243, 78], [224, 96, 49, 120, 243, 78], false),
            ([224, 96, 49, 120, 243, 78], [37, 46, 7, 91, 243, 78], true),
            ([37, 46, 7, 91, 243], [224, 96, 49, 120, 243, 78], false),
            ([1, 2, 3], [1, 2], true),
            ([224, 96, 49, 120, 243, 78], [224, 96, 49, 120, 243, 78], false),
        ]
        
        for (a, b, result) in abValues
        {
            let aa = BigInt(a)
            let bb = BigInt(b)
            let greaterThan = aa > bb
            
            XCTAssert(greaterThan == result, "Wrong result for \(aa) > \(bb)")
        }
    }

    func test_init_withUInt8Array_givesCorrectResult() {
    
        let a = BigInt([UInt8]([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x21, 0x34]))

        XCTAssert(a == BigInt(hexString: "3421f0debc9a78563412")!)
    }
    
    func test_init_withUInt16Array_givesCorrectResult() {
        
        let a = BigInt([UInt16]([0x1234, 0x5678, 0x9abc, 0xdef0, 0x2134]))
        
        XCTAssert(a == BigInt(hexString: "2134def09abc56781234")!)
    }

    func test_init_withUInt32Array_givesCorrectResult() {
        
        let a = BigInt([UInt32]([0x56789abc, 0xdef02134, 0x1234]))
        
        XCTAssert(a == BigInt(hexString: "1234def0213456789abc")!)
    }

    func test_init_withUInt64Array_givesCorrectResult() {
        
        let a = BigInt([UInt64]([0x56789abcdef02134, 0x1234]))
        
        XCTAssert(a == BigInt(hexString: "123456789abcdef02134")!)
    }

    func test_BigInt32init_withUInt64Array_givesCorrectResult() {
        
        let a = BigInt([UInt64]([0x56789abcdef02134, 0x1234]))
        let expectedResult = BigInt(hexString: "123456789abcdef02134")!

        XCTAssert(a == expectedResult)
    }

    func test_init_withHexString_givesCorrectResult() {
        
        let a = BigInt(hexString: "1234567890abcdefABCDEF")
        
        XCTAssert(a! == BigInt([0x7890abcdefABCDEF, 0x123456] as [UInt64]))
    }

    func test_init_withSomeHexString_givesCorrectResult() {
        
        let a = BigInt(hexString: "ffffffff12365981274ffffff1231265123ff")
        
        XCTAssert(a! == BigInt([0xffff1231265123ff, 0xfff12365981274ff, 0xfffff] as [UInt64]))
    }

    
    func test_toString__givesCorrectResult()
    {
        let hexString = "1234567890abcdefABCDEF"
        let a = BigInt(hexString: hexString)!
        
        XCTAssert(hexString.lowercased() == String(a).lowercased())
    }
    
    func BIGNUM_multiply(_ a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)

        var bn = BN_new()
        BN_hex2bn(&bn, b)

        let context = BN_CTX_new()
        let result = BN_new()
        BN_mul(result, an, bn, context)
        
        return String(validatingUTF8: BN_bn2hex(result))!
    }
    
    func BIGNUM_divide(_ a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)
        
        let context = BN_CTX_new()
        let result = BN_new()
        BN_div(result, nil, an, bn, context)
        
        return String(validatingUTF8: BN_bn2hex(result))!
    }

    func BIGNUM_mod(_ a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)
        
        let context = BN_CTX_new()
        let result = BN_new()
        BN_div(nil, result, an, bn, context)
        
        return String(validatingUTF8: BN_bn2hex(result))!
    }

    func BIGNUM_pow(_ a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)
        
        let context = BN_CTX_new()
        let result = BN_new()
        BN_exp(result, an, bn, context)
        
        return String(validatingUTF8: BN_bn2hex(result))!
    }

    func BIGNUM_mod_pow(_ a : String, _ b : String, _ mod : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)

        var modn = BN_new()
        BN_hex2bn(&modn, mod)

        let context = BN_CTX_new()
        let result = BN_new()
        BN_mod_exp_simple(result, an, bn, modn, context)
        
        return String(validatingUTF8: BN_bn2hex(result))!
    }

    func test_multiply_aNumberWithItself_givesCorrectResult()
    {
        let hexString = "123456789abcdef02134"
        let n = BigInt(hexString: hexString)!
        let nSquared = n * n
        
        let s = BIGNUM_multiply(hexString, hexString)
        
        let nString = String(nSquared)
        
        XCTAssert(nString.lowercased() == s.lowercased())
    }
    
    func test_multiply_twoNumbers_givesCorrectResult()
    {
        let aHex = "ffffffff12365981274ffffff1231265123ff"
        let bHex = "ffffffff26265235ffffff232323f23f23f232323f3243243f"
        let a = BigInt(hexString: aHex)!
        let b = BigInt(hexString: bHex)!
        let product = a * b
        
        let s = BIGNUM_multiply(aHex, bHex)
        
        let productHex = String(product)
        
        XCTAssert(productHex.lowercased() == s.lowercased())
    }

    func randomBigInt() -> BigInt
    {
        var parts = [UInt8]()
        let min = sizeof(BigInt.PrimitiveType.self)
        let max = min * 5
        repeat {
            let n = Int(arc4random()) % max + min
            parts = [UInt8]()
            
            for _ in 0..<n
            {
                parts.append(UInt8(arc4random() & 0xff))
            }
            
            while parts.last != nil && parts.last! == 0 {
                parts.removeLast()
            }
        
        } while parts.count < min
        
        return BigInt(parts)
    }
    
    func test_mod_withNegativeNumbers_givesCorrectResult()
    {
        let a = BigInt(hexString: "10000000000000000001", negative: true)!
        let b = BigInt(hexString: "10000000000000000000", negative: false)!
        
        let c = a % b
        
        XCTAssert(c == BigInt(-1))
    }
    
    func test_divide_twoNumbers_givesCorrectResult()
    {
        let uvValues : [(String, String)] = [
//            ("8fae", "e0"),
//            ("10000", "ffff"),
//            ("1000000", "ffff"),
//            ("100000", "10ff"),
            ("100000000000000000000000000000000", "ff000000000000000"),
//
//            ("ffffffff26265235ffffff232323f23f23f232323f3243243f", "ffffffff12365981274ffffff1231265123ff"),
//            ("A4F9B770F1A0A93F2880E44D1835EE3668B066401982AFA7BC44F3EA4A71D3594CA74BF7071B864106C7C1C862EE928336592C1F0C0C850F3A40E394C6BB71AE70461EE5C31F0D71E220FDFD755B3E921E1C32", "71FD484EBA7FBD7394"),
//            ("27C09B9E53EF44A877700C820071920F3287AC25BE1CCB9D857394AF862952A8CE6C73796A311E991A57B03324E3B1D298860A3FC41C28F218CB1F5A86C417DA44CEC597A2", "F10598D35D96090AD286A071DBA6BB324FFCDF1952E56C332B093F3C1786016509BBA6D229EB824A6A893BB5"),
//            ("D5B460CF20599FC4F81F", "7D2D049494FC")
        ]
        
        for (uHex, vHex) in uvValues {
           var u = BigInt(hexString: uHex)!
           var v = BigInt(hexString: vHex)!
        
//        for var i = 0; i < 100; ++i
//        {
//            var u = randomBigInt()
//            var v = randomBigInt()
            
//            var u = BigInt([0x57, 0x36, 0xbe, 0xa7] as [UInt8])
//            var v = BigInt([0xa4, 0xc3, 0xa7] as [UInt8])
//            var u = BigInt([0xaedc2883, 0x8680a05d, 0x92a2bf7f, 0x0053c30c] as [UInt32])
//            var v = BigInt([0x4884f56c, 0x0000e956] as [UInt32])

            if u < v {
                swap(&u, &v)
            }
            
            let s = BIGNUM_divide(String(u), String(v))

            let div = u / v
            
            let divHex = String(div)
            
            if divHex.lowercased() != s.lowercased() {
//                print("\(i):")
                print("Wrong division result for \(u) / \(v)")
                print("    Should be       \(s)\n" +
                      "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercased() == s.lowercased(), "Wrong division result for \(u) / \(v)")
        }
    }

    func test_CBigInt_divide_twoNumbers_givesCorrectResult()
    {
                let uvValues : [(String, String)] = [
//                    ("8fae", "e0"),
        //            ("10000", "ffff"),
        //            ("1000000", "ffff"),
        //            ("100000", "10ff"),
                    ("100000000000000000000000000000000", "ff000000000000000"),
        //
        //            ("ffffffff26265235ffffff232323f23f23f232323f3243243f", "ffffffff12365981274ffffff1231265123ff"),
        //            ("A4F9B770F1A0A93F2880E44D1835EE3668B066401982AFA7BC44F3EA4A71D3594CA74BF7071B864106C7C1C862EE928336592C1F0C0C850F3A40E394C6BB71AE70461EE5C31F0D71E220FDFD755B3E921E1C32", "71FD484EBA7FBD7394"),
                    ("27C09B9E53EF44A877700C820071920F3287AC25BE1CCB9D857394AF862952A8CE6C73796A311E991A57B03324E3B1D298860A3FC41C28F218CB1F5A86C417DA44CEC597A2", "F10598D35D96090AD286A071DBA6BB324FFCDF1952E56C332B093F3C1786016509BBA6D229EB824A6A893BB5"),
        //            ("D5B460CF20599FC4F81F", "7D2D049494FC")
                ]
        
        for (uHex, vHex) in uvValues {
            print(uHex)
            let u = CBigIntCreateWithHexString(uHex)!
            let v = CBigIntCreateWithHexString(vHex)!
            print(uHex)
            
            let s = BIGNUM_divide(uHex, vHex)
            print(uHex)
            
            let div = CBigIntDivide(u, v, nil)!
            print(uHex)
            
            let divHex = hexStringFromCBigInt(div)
            print(divHex)
            
            if divHex.lowercased() != s.lowercased() {
//                print("\(i):")
                print("Wrong division result for \(hexStringFromCBigInt(u)) / \(hexStringFromCBigInt(v))")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercased() == s.lowercased(), "Wrong division result for \(u) / \(v)")
        }
    }

    func test_mod_twoNumbers_givesCorrectResult()
    {
        for i in 0..<100
        {
            var u = randomBigInt()
            var v = randomBigInt()
        
//            var u = BigInt([0x57, 0x36, 0xbe, 0xa7] as [UInt8])
//            var v = BigInt([0xa4, 0xc3, 0xa7] as [UInt8])
        
            if u < v {
                swap(&u, &v)
            }
            
            let s = BIGNUM_mod(String(u), String(v))

            let div = u % v
            
            let divHex = String(div)
            
            if divHex.lowercased() != s.lowercased() {
                print("\(i):")
                print("Wrong mod result for \(u) % \(v)")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
           
            XCTAssert(divHex.lowercased() == s.lowercased(), "Wrong division result for \(u) / \(v)")
        }
    }

    func test_mod_pow_withTwoRandomNumbers_givesCorrectResult()
    {
        for i in 0..<100
        {
            let u = randomBigInt()
            let mod = randomBigInt()
            let n = Int(arc4random() % 10000)
            
            let s = BIGNUM_mod_pow(String(u), String(n, radix: 16), String(mod))
            
            let result = modular_pow(u, n, mod)
            
            let divHex = String(result)
            
            if divHex.lowercased() != s.lowercased() {
                print("\(i):")
                print("Wrong mod_pow result for \(u) % \(n)")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercased() == s.lowercased(), "Wrong mod_pow result for \(u) ^ \(n) % \(mod)")
        }
    }

    func test_mod_pow_withRandomBigIntExponent_givesCorrectResult()
    {
        for i in 0..<100
        {
            let u = BigInt(3)
            let mod = randomBigInt()
            let n = randomBigInt()
            
            let s = BIGNUM_mod_pow(String(u), String(n), String(mod))
            
            let result = modular_pow(u, n, mod)
            
            let divHex = String(result)
            
            if divHex.lowercased() != s.lowercased() {
                print("\(i):")
                print("Wrong mod_pow result for \(u) % \(n)")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercased() == s.lowercased(), "Wrong mod_pow result for \(u) ^ \(n) % \(mod)")
        }
    }

    func test_divideNumbers_numbersTriggerNegativeCaseInDivision_givesCorrectResult()
    {
        let u = BigInt([0xc5, 0x01, 0xbf] as [UInt8])
        let v = BigInt([0x5f, 0xb1, 0x0e] as [UInt8])

        let q = u / v
        
        
        XCTAssert(q == BigInt(0xc))
    }
    
    func test_extendedEuclid__givesCorrectResult()
    {
        let z = BigInt(5)
        let a = BigInt(13)
        let result = extended_euclid(z: z, a: a)
        print(result)
        
        XCTAssert(result == BigInt(-5))
    }
    
    func test_modularInverse__givesCorrectResult()
    {
        let x = BigInt(3)
        let y = BigInt(5)
        let a = BigInt(7)

        let result = modular_inverse(x, y, mod: a)
        
        XCTAssert(result == BigInt(2))
    }

    func test_isBitSet_someNumbers_givesCorrectResult()
    {
        let values : [(BigInt, Int, Bool)] = [
            (BigInt(0), 0, false),
            (BigInt(0x80), 7, true),
            (BigInt([0x00, 0x00, 0x80] as [UInt8]), 23, true),
            (BigInt([0x00, 0x00, 0x80] as [UInt8]), 22, false),
            (BigInt([0x01, 0x00, 0x00, 0x00, 0x80] as [UInt8]), 0, true),
            (BigInt([0x01, 0x00, 0x00, 0x00, 0x80] as [UInt8]), 39, true),
            (BigInt([0x01, 0x00, 0x00, 0x00, 0x80] as [UInt8]), 40, false),
        ]
        
        let shouldNot   = "should not"
        let should      = "should"
        for (n, bitNumber, isSet) in values
        {
            XCTAssert(n.isBitSet(bitNumber) == isSet, "isBitSet gives wrong result for \(n) where bit \(bitNumber) \(isSet ? should : shouldNot) be set.")
        }
    }
}
