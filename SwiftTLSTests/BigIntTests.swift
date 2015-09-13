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
            
            let s = BIGNUM_divide(u.toString(), v.toString())

            let div = u / v
            
            let divHex = div.toString()
            
            if divHex.lowercaseString != s.lowercaseString {
//                print("\(i):")
                print("Wrong division result for \(u.toString()) / \(v.toString())")
                print("    Should be       \(s)\n" +
                      "    but is actually \(divHex)")
            }
            
            XCTAssert(divHex.lowercaseString == s.lowercaseString, "Wrong division result for \(u) / \(v)")
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
            let u = CBigIntCreateWithHexString(uHex)
            let v = CBigIntCreateWithHexString(vHex)
            print(uHex)
            
            let s = BIGNUM_divide(uHex, vHex)
            print(uHex)
            
            let div = CBigIntDivide(u, v, nil)
            print(uHex)
            
            let divHex = hexStringFromCBigInt(div)
            print(divHex)
            
            if divHex.lowercaseString != s.lowercaseString {
//                print("\(i):")
                print("Wrong division result for \(hexStringFromCBigInt(u)) / \(hexStringFromCBigInt(v))")
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
        let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
        let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"

//        let generator = BigInt([2] as [UInt32], negative: false)
//        let exponent = BigInt([3116988641, 3983070910, 2701520770, 1363639321, 2557765447, 342272273, 2475071927, 2955743727, 2979479703, 715122230, 2343412841, 3499847595, 764462914, 263700299, 373275624, 1287566206] as [UInt32], negative: false)
//        let modulus = BigInt([1198843955, 3623894652, 503860470, 3793286365, 2731791378, 3614844779, 1771690793, 1464226003, 2319713261, 3985960860, 3087334159, 3712738611, 1867303570, 3504648053, 3649381001, 3663215638] as [UInt32], negative: false)

//        let generatorString = generator.toString()

        var an = BN_new()
        BN_hex2bn(&an, exponentString)
        
        var bn = BN_new()
        BN_hex2bn(&bn, modulusString)
        
        let context = BN_CTX_new()
        let result = BN_new()

        self.measureBlock() {
            for var i=0; i < 100; ++i {
                BN_mul(result, an, bn, context)
            }
//
//            modular_pow(generator, exponent, modulus)
        }
    }
    
    func test_multiply_performance()
    {
//        let generator = BigInt([2] as [UInt32], negative: false)
        let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
        let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"
        

        let exponent = BigInt(hexString: exponentString)!
        let modulus = BigInt(hexString: modulusString)!
        
        print(exponent.toString())
        print(modulus.toString())
        
        //        let generator = BigInt([2] as [UInt32], negative: false)
//        let exponent = BigInt([3116988641, 3983070910, 2701520770, 1363639321, 2557765447, 342272273, 2475071927, 2955743727, 2979479703, 715122230, 2343412841, 3499847595, 764462914, 263700299, 373275624, 1287566206] as [UInt32], negative: false)
//        let modulus = BigInt([1198843955, 3623894652, 503860470, 3793286365, 2731791378, 3614844779, 1771690793, 1464226003, 2319713261, 3985960860, 3087334159, 3712738611, 1867303570, 3504648053, 3649381001, 3663215638] as [UInt32], negative: false)
        
        self.measureBlock() {
            for var i=0; i < 100; ++i {
                exponent * modulus
//                print(result.toString())
            }
        }
    }
    
    func hexStringFromCBigInt(a : UnsafePointer<CBigInt>) -> String
    {
        let s = CBigIntHexString(a)
        
        let result = String.fromCString(s)!
        free(UnsafeMutablePointer<Void>(s))
        
        return result
    }
    
    func test_CBigInt_multiply_performance()
    {
        let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
        let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"

//        let exponentString = "abcdef0123456"
//        let modulusString = "abcdef012345678"

        let an = CBigIntCreateWithHexString(exponentString)
        let bn = CBigIntCreateWithHexString(modulusString)

        let anString = hexStringFromCBigInt(an)
        let bnString = hexStringFromCBigInt(bn)

        print(anString)
        print(bnString)

        assert(anString == exponentString)
        assert(bnString == modulusString)
        
        self.measureBlock() {
            for var i=0; i < 1000; ++i {
                CBigIntMultiply(an, bn)
//                print(self.hexStringFromCBigInt(result))
            }
        }
    }

    func test_BN_mod_pow_performance()
    {
        let generatorString = "02"
        let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
        let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"
        
        var exponent = BN_new()
        BN_hex2bn(&exponent, exponentString)

        var generator = BN_new()
        BN_hex2bn(&generator, generatorString)
        
        var modulus = BN_new()
        BN_hex2bn(&modulus, modulusString)
        
        let context = BN_CTX_new()
        let result = BN_new()
        
        self.measureBlock() {
//            for var i=0; i < 100; ++i {
                BN_mod_exp(result, generator, exponent, modulus, context)
//                print(String.fromCString(BN_bn2hex(result))!)
//            }
        }
    }

    func test_CBigInt_mod_pow_performance()
    {
        let generatorString = "02";
        let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
        let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"
        
        let exponent = CBigIntCreateWithHexString(exponentString)
        let generator = CBigIntCreateWithHexString(generatorString)
        let modulus = CBigIntCreateWithHexString(modulusString)
        
        self.measureBlock() {
//            for var i=0; i < 100; ++i {
                let result = CBigIntModularPowerWithBigIntExponent(generator, exponent, modulus)
//                print(self.hexStringFromCBigInt(result))
                CBigIntFree(result)
//            }
        }
    }

    func test_mod_pow_performance()
    {
//        let generator = BigInt([2] as [UInt32], negative: false)
//        let exponentString = "737328E34295F1F0808C5B49DE95074D2903CA6B4671C366DDACB0E81987E8D59273F1EEF33A464EE6C98E7F2980D380F5DA28224D2E98F93D073A8ED82EEA5136B92FC065EFAE8D6A94706B4A938DE702EC70FD87752722288D5C2C933CE323C7D4466DA2FD92661D23DBBABE29A4CE276BCCA4C2842B464DE6471C7F81F4CA62F239A3F16BBEB1FFAB93210EBC77F1425D880731D0605CE2C59A21B2F01B287EB6191ECCA9413F78202E6502A04310801B5E28AA139FC38C17EFAA31C7A8EB365AF759FAEC89DF2148855ABA21B1A0FBED53A7C72814CCC0439A65B41A1B42D69813B0AF781F27168A1ED439E74829151F658218E12513271B12849967B1DC80A72EFED413FECAF88A55E31A231CBB5778DE5179232931BDD1E2802BD4045E36941FBABC742E5C91B8E11026450FBEFDBB1B197816B818A41A4434292E1D2E929ADF1D841648670FAC9694AB38079A219141F61C86424CED5C258DDEE091760BC2CF57D02D29B8E0019D4B1B8A24E1087FBE0E2E2CC135F450B6FAD8D88D89"
//        let modulusString = "89C2E9AAB53A5F467EFF76F9D9DEB59268F867D819294AEAC35C84C8F3B77CA34C15D05AB4B6ABAB73DFD77F70324F41A4E80325A6A3FA939EE6E98B6AB5A330F9654FA1AD15E71E19347D223A203A3F8EA786386C5F8909A4F184255C93118D349C34AFB6C961A9AF9B563F243E21D99D65A3D6240321823BDE48705AA3C95469F65B4AD034174D99DDE24565D049FC008FA3032A0749E1E9F14B26E13F5DECF64B2A009CB8451289EDF3A5EBDF1A1C50676D1AA6BB496A25064E0828972EE7B12CADF9BC1DC4B3EADC23127C3AC67764A3FD8CFE042C7A33E2C5B154DC742119D1B16B42B637432768B7B720220055D1DF40EFE7AF6D28C492AC0B2EAF4D7FBF30F7160BB019353EE5D62D84500B148B1FBD15984A1E40E5CE3A4A5A4F22968D315AE60CB03E5A673ED0D770F3F0849E891DE99519D40459490A850BABE65F742FA70CEB5C531D1B964D60D2E5CA3FA3B45B9A6BE1E9B174DC2887D4CB9264E19BFA4DD2741AE66751D92147B93CB7031D3D9BDBC54F48C66BB8ECE6CD847B"
//        
//        
//        let exponent = BigInt(hexString: exponentString)!
//        let modulus = BigInt(hexString: modulusString)!
//        
//        print(exponent.toString())
//        print(modulus.toString())
//        
//        self.measureBlock() {
//            modular_pow(generator, exponent, modulus)
//        }

        self.measureBlock() {
            SwiftTLS_mod_pow_performance()
        }
    }

}
