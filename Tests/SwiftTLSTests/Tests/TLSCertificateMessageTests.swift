//
//  TLSCertificateMessageTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class TLSCertificateMessageTests: XCTestCase {
    static var allTests = [
        ("test_writeTo_withOneCertificate_givesDataFromWhichTheSameMessageCanBeConstructed", test_writeTo_withOneCertificate_givesDataFromWhichTheSameMessageCanBeConstructed),
    ]
    
    func test_writeTo_withOneCertificate_givesDataFromWhichTheSameMessageCanBeConstructed()
    {
        let certificatePath = path(forResource: "certificate.cer")
        let certificateData = try! Data(contentsOf: URL(fileURLWithPath: certificatePath))
        let certificate = X509.Certificate(derData: certificateData)!
        let sut = TLSCertificateMessage(certificates: [certificate])

        let context = TLSConnection()
        var data = [UInt8]()
        sut.writeTo(&data, context: context)
        let cert2Message = TLSCertificateMessage(inputStream: BinaryInputStream(data), context: context)!
        var data2 = [UInt8]()
        cert2Message.writeTo(&data2, context: context)
        
        XCTAssertEqual(data, data2)
    }
}
