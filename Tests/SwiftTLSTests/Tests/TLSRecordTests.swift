//
//  TLSRecordTests.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class TLSRecordTests: XCTestCase {
    static var allTests = [
        ("test_data_withBody_givesCorrectBinaryRepresention", test_data_withBody_givesCorrectBinaryRepresention),
        ("test_data_withContentTypeChangeCipherSpec_givesCorrectBinaryRepresention", test_data_withContentTypeChangeCipherSpec_givesCorrectBinaryRepresention),
        ("test_data_withContentTypeAlert_givesCorrectBinaryRepresention", test_data_withContentTypeAlert_givesCorrectBinaryRepresention),
        ("test_data_withContentTypeHandshake_givesCorrectBinaryRepresention", test_data_withContentTypeHandshake_givesCorrectBinaryRepresention),
    ]

    func test_data_withBody_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .changeCipherSpec, protocolVersion: .v1_2, body: [1,2,3,4,5])
        
        let data = [UInt8](record)
        
        XCTAssert(data == [UInt8]([20, 3, 3, 0, 5, 1, 2, 3, 4, 5]))
    }

    func test_data_withContentTypeChangeCipherSpec_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .changeCipherSpec, protocolVersion: .v1_2,body: [UInt8(0xff)])
        
        let data = [UInt8](record)
        
        XCTAssert(data == [UInt8]([20, 3, 3, 0, 1, 0xff]))
    }

    func test_data_withContentTypeAlert_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .alert, protocolVersion: .v1_2, body: [UInt8(0xff)])
        
        let data = [UInt8](record)
        
        XCTAssert(data == [UInt8]([21, 3, 3, 0, 1, 0xff]))
    }

    func test_data_withContentTypeHandshake_givesCorrectBinaryRepresention() {
        let record = TLSRecord(contentType: .handshake, protocolVersion: .v1_2, body: [UInt8(0xff)])
        
        let data = [UInt8](record)

        XCTAssert(data == [UInt8]([22, 3, 3, 0, 1, 0xff]))
    }



}
