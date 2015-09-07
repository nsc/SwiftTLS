//
//  BigIntTests.swift
//  Chat
//
//  Created by Nico Schmidt on 19.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
import OpenSSL
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
        
        let a = BigIntImpl<UInt32>([UInt64]([0x56789abcdef02134, 0x1234]))
        let expectedResult = BigIntImpl<UInt32>(hexString: "123456789abcdef02134")!

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
        BN_mul(result, an, bn, context)
        
        return String.fromCString(BN_bn2hex(result))!
    }
    
    func BIGNUM_divide(a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)
        
        let context = BN_CTX_new()
        let result = BN_new()
        BN_div(result, nil, an, bn, context)
        
        return String.fromCString(BN_bn2hex(result))!
    }

    func BIGNUM_mod(a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)
        
        let context = BN_CTX_new()
        let result = BN_new()
        BN_div(nil, result, an, bn, context)
        
        return String.fromCString(BN_bn2hex(result))!
    }

    func BIGNUM_pow(a : String, _ b : String) -> String
    {
        var an = BN_new()
        BN_hex2bn(&an, a)
        
        var bn = BN_new()
        BN_hex2bn(&bn, b)
        
        let context = BN_CTX_new()
        let result = BN_new()
        BN_exp(result, an, bn, context)
        
        return String.fromCString(BN_bn2hex(result))!
    }

    func BIGNUM_mod_pow(a : String, _ b : String, _ mod : String) -> String
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

    func randomBigInt() -> BigInt
    {
        var parts = [UInt8]()
        let min = sizeof(BigInt.PrimitiveType.self)
        let max = min * 5
        repeat {
            let n = Int(arc4random()) % max + min
            parts = [UInt8]()
            
            for var i = 0; i < n; ++i
            {
                parts.append(UInt8(arc4random() & 0xff))
            }
            
            while parts.last != nil && parts.last! == 0 {
                parts.removeLast()
            }
        
        } while parts.count < min
        
        return BigInt(parts)
    }
    
    func test_divide_twoNumbers_givesCorrectResult()
    {
//        let uvValues : [(String, String)] = [
//            ("8fae", "e0"),
//            ("10000", "ffff"),
//            ("1000000", "ffff"),
//            ("100000", "10ff"),
//            ("100000000000000000000000000000000", "ff000000000000000"),
//            
//            ("ffffffff26265235ffffff232323f23f23f232323f3243243f", "ffffffff12365981274ffffff1231265123ff"),
//            ("A4F9B770F1A0A93F2880E44D1835EE3668B066401982AFA7BC44F3EA4A71D3594CA74BF7071B864106C7C1C862EE928336592C1F0C0C850F3A40E394C6BB71AE70461EE5C31F0D71E220FDFD755B3E921E1C32", "71FD484EBA7FBD7394"),
//            ("27C09B9E53EF44A877700C820071920F3287AC25BE1CCB9D857394AF862952A8CE6C73796A311E991A57B03324E3B1D298860A3FC41C28F218CB1F5A86C417DA44CEC597A2", "F10598D35D96090AD286A071DBA6BB324FFCDF1952E56C332B093F3C1786016509BBA6D229EB824A6A893BB5"),
//            ("D5B460CF20599FC4F81F", "7D2D049494FC")
//        ]
        
//        for (uHex, vHex) in uvValues {
//           var u = BigInt(hexString: uHex)!
//           var v = BigInt(hexString: vHex)!
        
        for var i = 0; i < 100; ++i
        {
            var u = randomBigInt()
            var v = randomBigInt()
            
//            var u = BigInt([0x57, 0x36, 0xbe, 0xa7] as [UInt8])
//            var v = BigInt([0xa4, 0xc3, 0xa7] as [UInt8])
//            var u = BigInt([0xaedc2883, 0x8680a05d, 0x92a2bf7f, 0x0053c30c] as [UInt32])
//            var v = BigInt([0x4884f56c, 0x0000e956] as [UInt32])

            if u < v {
                swap(&u, &v)
            }
            
            let s = BIGNUM_divide(u.toString(), v.toString())

            let div = u / v
            
            let divHex = div.toString()
            
            if divHex.lowercaseString != s.lowercaseString {
                print("\(i):")
                print("Wrong division result for \(u.toString()) / \(v.toString())")
                print("    Should be       \(s)\n" +
                      "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercaseString == s.lowercaseString, "Wrong division result for \(u) / \(v)")
        }
    }

    func test_mod_twoNumbers_givesCorrectResult()
    {
        for var i = 0; i < 100; ++i
        {
            var u = randomBigInt()
            var v = randomBigInt()
        
//            var u = BigInt([0x57, 0x36, 0xbe, 0xa7] as [UInt8])
//            var v = BigInt([0xa4, 0xc3, 0xa7] as [UInt8])
        
            if u < v {
                swap(&u, &v)
            }
            
            let s = BIGNUM_mod(u.toString(), v.toString())

            let div = u % v
            
            let divHex = div.toString()
            
            if divHex.lowercaseString != s.lowercaseString {
                print("\(i):")
                print("Wrong mod result for \(u.toString()) % \(v.toString())")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
           
            XCTAssert(divHex.lowercaseString == s.lowercaseString, "Wrong division result for \(u) / \(v)")
        }
    }

    func test_mod_pow_withTwoRandomNumbers_givesCorrectResult()
    {
        for var i = 0; i < 100; ++i
        {
            let u = randomBigInt()
            let mod = randomBigInt()
            let n = Int(arc4random() % 10000)
            
            let s = BIGNUM_mod_pow(u.toString(), String(n, radix: 16), mod.toString())
            
            let result = modular_pow(u, n, mod)
            
            let divHex = result.toString()
            
            if divHex.lowercaseString != s.lowercaseString {
                print("\(i):")
                print("Wrong mod_pow result for \(u.toString()) % \(n)")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercaseString == s.lowercaseString, "Wrong mod_pow result for \(u) ^ \(n) % \(mod)")
        }
    }

    func test_mod_pow_withRandomBigIntExponent_givesCorrectResult()
    {
        for var i = 0; i < 100; ++i
        {
            let u = BigInt(3)
            let mod = randomBigInt()
            let n = randomBigInt()
            
            let s = BIGNUM_mod_pow(u.toString(), n.toString(), mod.toString())
            
            let result = modular_pow(u, n, mod)
            
            let divHex = result.toString()
            
            if divHex.lowercaseString != s.lowercaseString {
                print("\(i):")
                print("Wrong mod_pow result for \(u.toString()) % \(n)")
                print("    Should be       \(s)\n" +
                    "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercaseString == s.lowercaseString, "Wrong mod_pow result for \(u) ^ \(n) % \(mod)")
        }
    }

    func test_divideNumbers_numbersTriggerNegativeCaseInDivision_givesCorrectResult()
    {
        let u = BigInt([0xc5, 0x01, 0xbf] as [UInt8])
        let v = BigInt([0x5f, 0xb1, 0x0e] as [UInt8])

        let q = u / v
        
        
        XCTAssert(q == BigInt(0xc))
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
    
    func test_BN_multiply_performance()
    {
//        let generator = BigInt([2] as [UInt32], negative: false)
        let exponent = BigInt([3638070665, 4098930426, 774684981, 142589454, 462038241, 3758202187, 3492620728, 197316439, 3739259254, 3982239117, 478560844, 563167734, 2872575898, 262968980, 2216052839, 2459623197, 690887982, 2753184820, 2014754840, 4256897817, 642060222, 2444812560, 3161730652, 915677114, 735315038, 3184648832, 2032347441, 1467539025, 438508731, 4169815523, 3558080202, 2158440190, 2573709788, 656085636, 417408275, 354379138, 971458601, 378150612, 2943885095, 3600290736, 3021609794, 3225655909, 3341292748, 4226634663, 3122770336, 558400858, 4209805791, 911931225, 835168491, 2350378922, 2853412803, 2149277224, 44057360, 2015374949, 3433644351, 2125863198, 3002080040, 3804600865, 835739740, 1113425927, 247232497, 4289434401, 4050370225, 1660041635, 2139223242, 1306937116, 3263441734, 661376164, 3190400206, 488889274, 2734527078, 3352577645, 2470241059, 680352812, 2272601890, 49049853, 1251184103, 1788113003, 1710206605, 918106048, 3626953297, 1023883918, 1294899449, 4124715042, 696308608, 3871968895, 4080682574, 2457072110, 428337365, 3719082216, 1181860710, 688114283, 3734308685, 2156682057, 1117123056, 1936926947] as [UInt32], negative: false)
        let modulus = BigInt([3872228475, 3328948460, 3687141192, 52247963, 1203322039, 1733417249, 3530824422, 3785095757, 3570111076, 1960585351, 1809967537, 2746506138, 3538274879, 462835040, 3948696349, 1949280012, 195815007, 1497959045, 2501497860, 2659786217, 1895035012, 1732169943, 212876890, 2368821990, 1515135638, 3855497802, 2554994240, 2334113045, 2219838228, 1055249965, 196090165, 3207657238, 783240575, 3297946635, 3887033640, 3521069295, 539099221, 661174199, 1119237955, 433172843, 1423733793, 870499761, 4261686394, 1688468876, 2084226679, 3940295442, 3156067507, 2972495353, 680996583, 621170184, 2797291882, 1348955418, 3957266972, 2314072997, 2629322002, 4132121088, 3779026412, 3924904742, 705120737, 9413379, 1708149244, 2581455429, 3493074765, 1777752906, 1520683348, 1004423280, 604184962, 2640683990, 608051673, 2946192959, 3066651049, 882652335, 1553142157, 2767291429, 1818200329, 2393343544, 975190591, 422870306, 2903893790, 4184166305, 1790288688, 2665933195, 2795764371, 2766668581, 1882345281, 1944049535, 3031870379, 1276498010, 4088888483, 3277620424, 422136554, 1761109976, 3655251346, 2130671353, 3040501574, 2311252394] as [UInt32], negative: false)

//        let generator = BigInt([2] as [UInt32], negative: false)
//        let exponent = BigInt([3116988641, 3983070910, 2701520770, 1363639321, 2557765447, 342272273, 2475071927, 2955743727, 2979479703, 715122230, 2343412841, 3499847595, 764462914, 263700299, 373275624, 1287566206] as [UInt32], negative: false)
//        let modulus = BigInt([1198843955, 3623894652, 503860470, 3793286365, 2731791378, 3614844779, 1771690793, 1464226003, 2319713261, 3985960860, 3087334159, 3712738611, 1867303570, 3504648053, 3649381001, 3663215638] as [UInt32], negative: false)

//        let generatorString = generator.toString()
        let exponentString = exponent.toString()
        let modulusString = modulus.toString()
        
        var an = BN_new()
        BN_hex2bn(&an, exponentString)
        
        var bn = BN_new()
        BN_hex2bn(&bn, modulusString)
        
        let context = BN_CTX_new()
        let result = BN_new()

        self.measureBlock() {
            for var i=0; i < 1000; ++i {
                BN_mul(result, an, bn, context)
            }
//
//            modular_pow(generator, exponent, modulus)
        }
    }
    
    func test_multiply_performance()
    {
        //        let generator = BigInt([2] as [UInt32], negative: false)
//        let exponent = BigInt([3638070665, 4098930426, 774684981, 142589454, 462038241, 3758202187, 3492620728, 197316439, 3739259254, 3982239117, 478560844, 563167734, 2872575898, 262968980, 2216052839, 2459623197, 690887982, 2753184820, 2014754840, 4256897817, 642060222, 2444812560, 3161730652, 915677114, 735315038, 3184648832, 2032347441, 1467539025, 438508731, 4169815523, 3558080202, 2158440190, 2573709788, 656085636, 417408275, 354379138, 971458601, 378150612, 2943885095, 3600290736, 3021609794, 3225655909, 3341292748, 4226634663, 3122770336, 558400858, 4209805791, 911931225, 835168491, 2350378922, 2853412803, 2149277224, 44057360, 2015374949, 3433644351, 2125863198, 3002080040, 3804600865, 835739740, 1113425927, 247232497, 4289434401, 4050370225, 1660041635, 2139223242, 1306937116, 3263441734, 661376164, 3190400206, 488889274, 2734527078, 3352577645, 2470241059, 680352812, 2272601890, 49049853, 1251184103, 1788113003, 1710206605, 918106048, 3626953297, 1023883918, 1294899449, 4124715042, 696308608, 3871968895, 4080682574, 2457072110, 428337365, 3719082216, 1181860710, 688114283, 3734308685, 2156682057, 1117123056, 1936926947] as [UInt32], negative: false)
//        let modulus = BigInt([3872228475, 3328948460, 3687141192, 52247963, 1203322039, 1733417249, 3530824422, 3785095757, 3570111076, 1960585351, 1809967537, 2746506138, 3538274879, 462835040, 3948696349, 1949280012, 195815007, 1497959045, 2501497860, 2659786217, 1895035012, 1732169943, 212876890, 2368821990, 1515135638, 3855497802, 2554994240, 2334113045, 2219838228, 1055249965, 196090165, 3207657238, 783240575, 3297946635, 3887033640, 3521069295, 539099221, 661174199, 1119237955, 433172843, 1423733793, 870499761, 4261686394, 1688468876, 2084226679, 3940295442, 3156067507, 2972495353, 680996583, 621170184, 2797291882, 1348955418, 3957266972, 2314072997, 2629322002, 4132121088, 3779026412, 3924904742, 705120737, 9413379, 1708149244, 2581455429, 3493074765, 1777752906, 1520683348, 1004423280, 604184962, 2640683990, 608051673, 2946192959, 3066651049, 882652335, 1553142157, 2767291429, 1818200329, 2393343544, 975190591, 422870306, 2903893790, 4184166305, 1790288688, 2665933195, 2795764371, 2766668581, 1882345281, 1944049535, 3031870379, 1276498010, 4088888483, 3277620424, 422136554, 1761109976, 3655251346, 2130671353, 3040501574, 2311252394] as [UInt32], negative: false)
        
        //        let generator = BigInt([2] as [UInt32], negative: false)
        let exponent = BigInt([3116988641, 3983070910, 2701520770, 1363639321, 2557765447, 342272273, 2475071927, 2955743727, 2979479703, 715122230, 2343412841, 3499847595, 764462914, 263700299, 373275624, 1287566206] as [UInt32], negative: false)
        let modulus = BigInt([1198843955, 3623894652, 503860470, 3793286365, 2731791378, 3614844779, 1771690793, 1464226003, 2319713261, 3985960860, 3087334159, 3712738611, 1867303570, 3504648053, 3649381001, 3663215638] as [UInt32], negative: false)
        
        self.measureBlock() {
            for var i=0; i < 1000; ++i {
                exponent * modulus
            }
        }
    }

}
