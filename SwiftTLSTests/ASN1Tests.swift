//
//  ASN1Tests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import swifttls

class ASN1Tests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_read_DHParams () {
        if let parser = ASN1Parser(PEMFile: "SwiftTLSTests/dhparams.pem") {
            if let sequence = parser.parseObject() as? ASN1Sequence {
                XCTAssert(sequence.objects.count == 2)
                
                if let prime = sequence.objects[0] as? ASN1Integer {
                    XCTAssert(true)
                }
                else {
                    XCTFail()
                }
                
                if let generator = sequence.objects[1] as? ASN1Integer {
                    XCTAssert(true)
                }
                else {
                    XCTFail()
                }

            }
            
        }
    }

//    func test_read_certificate() {
//        if let parser = ASN1Parser(PEMFile: "/Users/nico/tmp/pubkey.pem") {
//            if let object = parser.parseObject() {
//                ASN1_print_recursive(object)
//            }
//        }
//    }

    func test_parseObject_withATrueBooleanEncoded_givesCorrectResult() {
        if let boolean = ASN1Parser(data: [0x01, 0x01, 0xff]).parseObject() as? ASN1Boolean {
            XCTAssertTrue(boolean.value)
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withAFalseBooleanEncoded_givesCorrectResult() {
        if let boolean = ASN1Parser(data: [0x01, 0x01, 0x00]).parseObject() as? ASN1Boolean {
            XCTAssertFalse(boolean.value)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_parseObject_withAnOneByteIntegerEncoded_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x02, 0x01, 0x03]).parseObject() as? ASN1Integer {
            XCTAssertTrue(value.value[0] == UInt8(3))
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withAnOneByteBEREncodedEncoded_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x02, 0x81, 0x01, 0x03]).parseObject() as? ASN1Integer {
            XCTAssertTrue(value.value[0] == UInt8(3))
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withDEREncodedBitString1_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 6)
            XCTAssertTrue(value.bitValue[0] == 0b011011100101110111)
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withDEREncodedBitString2_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x0b, 0x01, 0x27, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x27]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 1)
            var bitValue = value.bitValue
            XCTAssertTrue(bitValue[0] == 0x1391)
            XCTAssertTrue(UInt64(bitValue[1]) == 0x9191919191919193 as UInt64)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_parseObject_withDEREncodedBitString3_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x11, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 0)
            var bitValue = value.bitValue
            XCTAssertTrue(bitValue[0] == 0x123456789abcdef1)
            XCTAssertTrue(bitValue[1] == 0x23456789abcdef12)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_parseObject_withBERConstructedEncodedBitString_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x11, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 0)
            var bitValue = value.bitValue
            XCTAssertTrue(bitValue[0] == 0x123456789abcdef1)
            XCTAssertTrue(bitValue[1] == 0x23456789abcdef12)
            return
        }
        else {
            XCTFail()
        }
    }




    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }

}
