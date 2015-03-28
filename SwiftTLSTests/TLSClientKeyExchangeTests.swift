//
//  TLSClientKeyExchangeTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

class TLSClientKeyExchangeTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_writeTo__givesDataFromWhichTheSameMessageCanBeConstructed()
    {
        class SUT : TLSClientKeyExchange
        {
            init!()
            {
                var encryptedPreMasterSecret : [UInt8] = [
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
                var data = DataBuffer()
                write(data, TLSHandshakeType.ClientKeyExchange.rawValue)
                writeUInt24(data, encryptedPreMasterSecret.count)
                write(data, encryptedPreMasterSecret)
                super.init(inputStream: BinaryInputStream(data: data.buffer))
            }

            required init?(inputStream: InputStreamType) {
                fatalError("init(inputStream:) has not been implemented")
            }
        }
        
        var data = DataBuffer()
        SUT().writeTo(&data)
        var msg2 = TLSClientKeyExchange(inputStream: BinaryInputStream(data: data.buffer))!
        var data2 = DataBuffer()
        msg2.writeTo(&data2)
        
        XCTAssertEqual(data.buffer, data2.buffer)
    }

}
