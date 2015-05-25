//
//  ASN1Tests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

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

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }

}
