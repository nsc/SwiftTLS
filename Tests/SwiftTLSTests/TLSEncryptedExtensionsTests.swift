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

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_writeTo_withSomeExtensions_givesDataFromWhichTheSameMessageCanBeConstructed() {
        let encryptedExtensions = TLS1_3.TLSEncryptedExtensions(extensions: [])
        
        let context = TLSConnection(configuration: TLSConfiguration(supportedVersions: [.v1_3]))
        var data: [UInt8] = []
        encryptedExtensions.writeTo(&data, context: context)
        
        if let copy = TLS1_3.TLSEncryptedExtensions(inputStream: BinaryInputStream(data), context: context) {
//            XCTAssert(encryptedExtensions.extensions == copy.extensions)
        }
        else {
            XCTFail()
        }
    }
}
