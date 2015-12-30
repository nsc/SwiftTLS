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
    
    func test_something()
    {
//        let signature : [UInt8] = [84, 109, 160, 23, 95, 20, 207, 109, 101, 50, 181, 93, 139, 81, 180, 0, 156, 241, 241, 204, 49, 77, 31, 58, 89, 4, 200, 145, 7, 135, 157, 190, 152, 8, 84, 70, 163, 3, 226, 178, 122, 16, 180, 231, 140, 208, 91, 130, 65, 253, 175, 163, 217, 59, 81, 119, 86, 215, 249, 105, 248, 153, 150, 250, 182, 157, 39, 218, 51, 18, 77, 193, 216, 155, 37, 48, 148, 199, 107, 29, 132, 156, 122, 180, 193, 19, 234, 21, 95, 234, 143, 83, 23, 65, 76, 55, 180, 162, 35, 41, 92, 235, 87, 194, 172, 70, 186, 23, 100, 95, 40, 32, 127, 241, 219, 171, 159, 226, 130, 236, 204, 13, 235, 225, 197, 109, 150, 218, 25, 247, 200, 216, 97, 163, 221, 159, 169, 237, 52, 114, 163, 103, 190, 210, 81, 49, 151, 16, 172, 255, 34, 131, 210, 129, 180, 215, 165, 140, 164, 235, 90, 239, 74, 13, 20, 81, 57, 143, 12, 173, 8, 31, 11, 146, 191, 234, 254, 222, 246, 186, 135, 77, 2, 73, 121, 132, 155, 99, 83, 82, 89, 136, 183, 209, 121, 102, 135, 235, 84, 51, 162, 82, 172, 152, 76, 236, 147, 5, 67, 154, 26, 53, 115, 247, 10, 195, 82, 121, 80, 87, 244, 1, 175, 134, 35, 82, 174, 151, 99, 35, 235, 76, 172, 112, 38, 45, 75, 67, 18, 54, 236, 31, 217, 200, 248, 131, 130, 246, 146, 253, 60, 207, 240, 178, 39, 10]
        
        let signature : [UInt8] = [108, 11, 141, 250, 22, 12, 76, 138, 99, 81, 167, 116, 99, 80, 211, 57, 177, 250, 209, 68, 23, 37, 2, 232, 123, 105, 96, 33, 207, 61, 34, 193, 77, 110, 205, 244, 253, 49, 88, 62, 85, 55, 3, 138, 216, 235, 248, 32, 69, 101, 234, 231, 111, 163, 252, 187, 69, 238, 3, 66, 110, 190, 140, 251, 108, 2, 17, 71, 117, 115, 168, 201, 76, 138, 179, 190, 73, 207, 109, 59, 255, 181, 180, 117, 43, 217, 133, 88, 179, 153, 164, 125, 27, 34, 244, 169, 20, 219, 83, 199, 241, 3, 30, 21, 217, 19, 239, 82, 86, 154, 155, 98, 84, 8, 72, 80, 126, 174, 178, 179, 70, 145, 3, 98, 11, 24, 16, 19, 184, 220, 157, 176, 43, 127, 114, 236, 63, 190, 104, 219, 179, 52, 51, 136, 120, 84, 102, 146, 67, 200, 51, 102, 155, 129, 66, 47, 131, 39, 9, 86, 73, 195, 186, 70, 122, 153, 109, 225, 118, 6, 109, 154, 174, 156, 203, 53, 240, 48, 208, 212, 218, 206, 165, 187, 109, 159, 126, 23, 33, 208, 84, 14, 60, 7, 233, 160, 158, 64, 139, 248, 248, 90, 160, 201, 23, 87, 180, 237, 124, 47, 130, 94, 220, 195, 37, 191, 51, 26, 51, 237, 155, 141, 106, 106, 28, 207, 220, 96, 204, 20, 89, 33, 210, 198, 36, 174, 252, 3, 27, 65, 224, 57, 62, 50, 108, 92, 3, 239, 240, 6, 193, 216, 162, 204, 36, 48]
        
        let data : [UInt8] = [48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 98, 237, 221, 227, 71, 31, 152, 88, 212, 75, 57, 84, 169, 125, 160, 210, 47, 66, 64, 240]
        
        
        let sequence = ASN1Parser(data: data).parseObject() as! ASN1Sequence
        
        for object in sequence.objects {
            print(object)
        }
        
        let certificatePath = NSBundle(forClass: self.dynamicType).URLForResource("mycert.pem", withExtension: nil)!.path!
        
        guard let rsa = RSA.fromCertificateFile(certificatePath) else {
            XCTFail()
            return
        }

        let m = rsa.verify(signature, data: data)
        
        print(m)
    }
    
//    func test_padding()
//    {
//        let rsa = RSA()
//    }
    
    func test_sign_someData_verifies()
    {
        let certificatePath = NSBundle(forClass: self.dynamicType).URLForResource("mycert.pem", withExtension: nil)!.path!

        guard let rsa = RSA.fromCertificateFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = rsa.signData(data)
        
        print(signature)
        
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
