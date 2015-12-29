//
//  RSATests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class RSATests: XCTestCase {

    func test_sign_someData_verifies()
    {
        let certificatePath = NSBundle(forClass: self.dynamicType).URLForResource("mycert.pem", withExtension: nil)!.path!

        guard let rsa = RSA.fromCertificateFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = rsa.signData(data)
        
        let rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        let verified = rsa2.verifySignature(signature, data: data)
        
        XCTAssert(verified)
    }

    func test_decrypt_encryptedData_givesOriginalData()
    {
        let certificatePath = NSBundle(forClass: self.dynamicType).URLForResource("mycert.pem", withExtension: nil)!.path!
        
        guard let rsa = RSA.fromCertificateFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        let rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        let encrypted = rsa2.encrypt(data)
        print(encrypted)
        
        let decrypted = rsa.decrypt(encrypted)
        print(decrypted)
        
        XCTAssert(data == decrypted)
    }

}
