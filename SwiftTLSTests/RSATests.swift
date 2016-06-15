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
        let signature : [UInt8] = [108, 11, 141, 250, 22, 12, 76, 138, 99, 81, 167, 116, 99, 80, 211, 57, 177, 250, 209, 68, 23, 37, 2, 232, 123, 105, 96, 33, 207, 61, 34, 193, 77, 110, 205, 244, 253, 49, 88, 62, 85, 55, 3, 138, 216, 235, 248, 32, 69, 101, 234, 231, 111, 163, 252, 187, 69, 238, 3, 66, 110, 190, 140, 251, 108, 2, 17, 71, 117, 115, 168, 201, 76, 138, 179, 190, 73, 207, 109, 59, 255, 181, 180, 117, 43, 217, 133, 88, 179, 153, 164, 125, 27, 34, 244, 169, 20, 219, 83, 199, 241, 3, 30, 21, 217, 19, 239, 82, 86, 154, 155, 98, 84, 8, 72, 80, 126, 174, 178, 179, 70, 145, 3, 98, 11, 24, 16, 19, 184, 220, 157, 176, 43, 127, 114, 236, 63, 190, 104, 219, 179, 52, 51, 136, 120, 84, 102, 146, 67, 200, 51, 102, 155, 129, 66, 47, 131, 39, 9, 86, 73, 195, 186, 70, 122, 153, 109, 225, 118, 6, 109, 154, 174, 156, 203, 53, 240, 48, 208, 212, 218, 206, 165, 187, 109, 159, 126, 23, 33, 208, 84, 14, 60, 7, 233, 160, 158, 64, 139, 248, 248, 90, 160, 201, 23, 87, 180, 237, 124, 47, 130, 94, 220, 195, 37, 191, 51, 26, 51, 237, 155, 141, 106, 106, 28, 207, 220, 96, 204, 20, 89, 33, 210, 198, 36, 174, 252, 3, 27, 65, 224, 57, 62, 50, 108, 92, 3, 239, 240, 6, 193, 216, 162, 204, 36, 48]
        
        let data : [UInt8] = [48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 98, 237, 221, 227, 71, 31, 152, 88, 212, 75, 57, 84, 169, 125, 160, 210, 47, 66, 64, 240]
        
        
        let sequence = ASN1Parser(data: data).parseObject() as! ASN1Sequence
        
        for object in sequence.objects {
            print(object)
        }
        
        let certificatePath = Bundle(for: self.dynamicType).urlForResource("mycert.pem", withExtension: nil)!.path!
        
        guard let rsa = RSA.fromCertificateFile(certificatePath) else {
            XCTFail()
            return
        }

        let m = rsa.verify(signature: signature, data: data)
        
        print(m)
    }
    
    func test_sign_someData_verifies()
    {
        let certificatePath = Bundle(for: self.dynamicType).urlForResource("mycert.pem", withExtension: nil)!.path!

        guard let rsa = RSA.fromCertificateFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = rsa.signData(data, hashAlgorithm: .sha1)
        
        print(signature)
        
        let rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        let verified = rsa2.verifySignature(signature, data: data)
        
        XCTAssert(verified)
    }

    func test_decrypt_encryptedData_givesOriginalData()
    {
        let certificatePath = Bundle(for: self.dynamicType).urlForResource("mycert.pem", withExtension: nil)!.path!
        
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

    func test_verify_signatureFromSelfSignedRSACertificate_verifies()
    {
        let certificatePath = Bundle(for: self.dynamicType).pathForResource("Self Signed RSA Certificate.cer", ofType: "")!
        let data = (try! Data(contentsOf: URL(fileURLWithPath: certificatePath))).UInt8Array()
        
        guard let cert = X509.Certificate(DERData: data) else { XCTFail(); return }
        
        let tbsData     = cert.tbsCertificate.DEREncodedCertificate!
        let publicKey   = cert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
        XCTAssert(publicKey.numberOfBits == publicKey.bits.count * 8)
        
        let rsa         = RSA(publicKey: publicKey.bits)

        let verified = rsa!.verify(signature: cert.signatureValue.bits, data: tbsData)

        XCTAssert(verified)
    }
}
