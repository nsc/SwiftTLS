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
        let record = TLSRecord(contentType: .ChangeCipherSpec, protocolVersion: .TLS_v1_2, body: [1,2,3,4,5])
        
        let data = DataBuffer(record).buffer
        
        XCTAssert(data == [UInt8]([20, 3, 3, 0, 5, 1, 2, 3, 4, 5]))
    }

    func test_data_withContentTypeChangeCipherSpec_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .ChangeCipherSpec, protocolVersion: .TLS_v1_2,body: [UInt8(0xff)])
        
        let data = DataBuffer(record).buffer
        
        XCTAssert(data == [UInt8]([20, 3, 3, 0, 1, 0xff]))
    }

    func test_data_withContentTypeAlert_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .Alert, protocolVersion: .TLS_v1_2, body: [UInt8(0xff)])
        
        let data = DataBuffer(record).buffer
        
        XCTAssert(data == [UInt8]([21, 3, 3, 0, 1, 0xff]))
    }

    func test_data_withContentTypeHandshake_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .Handshake, protocolVersion: .TLS_v1_2, body: [UInt8(0xff)])
        
        let data = DataBuffer(record).buffer

        XCTAssert(data == [UInt8]([22, 3, 3, 0, 1, 0xff]))
    }



}
