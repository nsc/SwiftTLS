//
//  TLSReadExtensionsTests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 29.07.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest

@testable import SwiftTLS

class TLSReadExtensionsTests: XCTestCase {
    static var allTests = [
        ("test_TLSReadExtensions_withMaliciouslyCraftedInput_doesntGetStuck", test_TLSReadExtensions_withMaliciouslyCraftedInput_doesntGetStuck),
    ]

    func test_TLSReadExtensions_withMaliciouslyCraftedInput_doesntGetStuck() {
        var extensions: [UInt8] = []
        TLSWriteExtensions(&extensions,
                           extensions: [TLSEllipticCurvePointFormatsExtension(ellipticCurvePointFormats: [.uncompressed])],
                           messageType: .clientHello,
                           context: nil)
        
        
        let appendedBytes: [UInt8] = [0x02, 0x00]
        extensions.append(contentsOf: appendedBytes)

        // Reset length
        var length = Int(extensions[0]) * 256 + Int(extensions[1])
        length += appendedBytes.count
        extensions[0] = UInt8(length >> 8)
        extensions[1] = UInt8(length & 0xff)
        
        let result = TLSReadExtensions(from: BinaryInputStream(extensions), length: extensions.count, messageType: .clientHello, context: nil)
        
        XCTAssert(result.first as? TLSEllipticCurvePointFormatsExtension != nil)
    }
}
