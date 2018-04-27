//
//  TLSEncryptedExtensionsTests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 02.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class TLSEncryptedExtensionsTests: XCTestCase {
    static var allTests = [
        ("test_writeTo_withSomeExtensions_givesDataFromWhichTheSameMessageCanBeConstructed", test_writeTo_withSomeExtensions_givesDataFromWhichTheSameMessageCanBeConstructed),
    ]

    func test_writeTo_withSomeExtensions_givesDataFromWhichTheSameMessageCanBeConstructed() {
        let encryptedExtensions = TLS1_3.TLSEncryptedExtensions(extensions: [])
        
        let context = TLSConnection(configuration: TLSConfiguration(supportedVersions: [.v1_3]))
        var data: [UInt8] = []
        encryptedExtensions.writeTo(&data, context: context)
        
        if TLS1_3.TLSEncryptedExtensions(inputStream: BinaryInputStream(data), context: context) == nil {
            XCTFail()
        }
    }
}
