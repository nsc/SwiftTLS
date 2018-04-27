//
//  TLSClientKeyExchangeTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class TLSClientKeyExchangeTests: XCTestCase {
    static var allTests = [
        ("test_writeTo__givesDataFromWhichTheSameMessageCanBeConstructed", test_writeTo__givesDataFromWhichTheSameMessageCanBeConstructed),
    ]

    func test_writeTo__givesDataFromWhichTheSameMessageCanBeConstructed()
    {
        class SUT : TLSClientKeyExchange
        {
            init!()
            {
                let encryptedPreMasterSecret : [UInt8] = [
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
                
                var data = [UInt8]()
                data.write(TLSHandshakeType.clientKeyExchange.rawValue)
                data.writeUInt24(encryptedPreMasterSecret.count)
                data.write(UInt16(encryptedPreMasterSecret.count))
                data.write(encryptedPreMasterSecret)
                super.init(inputStream: BinaryInputStream(data), context: TLSConnection())
            }

            required init?(inputStream: InputStreamType, context: TLSConnection) {
                fatalError("init(inputStream:) has not been implemented")
            }
        }
        
        let context = TLSConnection()
        var data = [UInt8]()
        SUT().writeTo(&data, context: context)
        let msg2 = TLSClientKeyExchange(inputStream: BinaryInputStream(data), context: context)!
        var data2 = [UInt8]()
        msg2.writeTo(&data2, context: context)
        
        XCTAssertEqual(data, data2)
    }

}
