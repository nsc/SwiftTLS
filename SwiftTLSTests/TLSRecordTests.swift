//
//  TLSRecordTests.swift
//  Chat
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

class TLSRecordTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_data_withBody_givesCorrectBinaryRepresention() {
        var record = TLSRecord(contentType: .ChangeCipherSpec, body: [1,2,3,4,5])
        
        var data = DataBuffer(record).buffer
        
        XCTAssert(data == [UInt8]([20, 3, 1, 0, 5, 1, 2, 3, 4, 5]))
    }

    func test_data_withContentTypeChangeCipherSpec_givesCorrectBinaryRepresention() {
        var record = TLSRecord(contentType: .ChangeCipherSpec, body: [UInt8(0xff)])
        
        var data = DataBuffer(record).buffer
        
        XCTAssert(data == [UInt8]([20, 3, 1, 0, 1, 0xff]))
    }

    func test_data_withContentTypeAlert_givesCorrectBinaryRepresention() {
        var record = TLSRecord(contentType: .Alert, body: [UInt8(0xff)])
        
        var data = DataBuffer(record).buffer
        
        XCTAssert(data == [UInt8]([21, 3, 1, 0, 1, 0xff]))
    }

    func test_data_withContentTypeHandshake_givesCorrectBinaryRepresention() {
        var record = TLSRecord(contentType: .Handshake, body: [UInt8(0xff)])
        
        var data = DataBuffer(record).buffer

        XCTAssert(data == [UInt8]([22, 3, 1, 0, 1, 0xff]))
    }



}
