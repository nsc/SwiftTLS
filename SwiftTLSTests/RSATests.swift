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
        let certificatePath = Bundle(for: type(of: self)).url(forResource: "mycert.pem", withExtension: nil)!.path

        guard var rsa = RSA.fromPEMFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let signatureScheme = TLSSignatureScheme.rsa_pkcs1_sha1
        rsa.signatureScheme = signatureScheme
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = try! rsa.signData(data)
        
        print(signature)
        
        var rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        rsa2.signatureScheme = signatureScheme
        let verified = try! rsa2.verifySignature(signature, data: data)
        
        XCTAssert(verified)
    }

    func test_decrypt_encryptedData_givesOriginalData()
    {
        let certificatePath = Bundle(for: type(of: self)).url(forResource: "mycert.pem", withExtension: nil)!.path
        
        guard let rsa = RSA.fromPEMFile(certificatePath) else {
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
        let certificatePath = Bundle(for: type(of: self)).path(forResource: "Self Signed RSA SHA-256.cer", ofType: "")!
        let data = (try! Data(contentsOf: URL(fileURLWithPath: certificatePath))).UInt8Array()
        
        guard let cert = X509.Certificate(derData: data) else { XCTFail(); return }
        
        let tbsData     = cert.tbsCertificate.DEREncodedCertificate!
        let publicKey   = cert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
        XCTAssert(publicKey.numberOfBits == publicKey.bits.count * 8)
        
        let rsa         = RSA(publicKey: publicKey.bits)

        let verified = try! rsa!.verify(signature: cert.signatureValue.bits, data: tbsData)

        XCTAssert(verified)
    }
    
    func test_RSA_PSS_sign_someData_verifies()
    {
        let certificatePath = Bundle(for: type(of: self)).url(forResource: "mycert.pem", withExtension: nil)!.path
        
        guard var rsa = RSA.fromPEMFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let signatureScheme = TLSSignatureScheme.rsa_pss_sha256
        rsa.signatureScheme = signatureScheme

        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = try! rsa.ssa_pss_sign(message: data)
        
        print(signature)
        
        var rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        rsa2.signatureScheme = signatureScheme

        let verified = try! rsa2.ssa_pss_verify(message: data, signature: signature)
        
        XCTAssert(verified)
    }

//    func test_encrypt_givesSameResultAsSecurityFramework() {
//        let certificatePath = Bundle(for: self.dynamicType).url(forResource: "mycert2.pem", withExtension: nil)!.path!
//        
//        guard let rsa = RSA.fromPEMFile(certificatePath) else {
//            XCTFail()
//            return
//        }
//
//        let data = [1,2,3] as [UInt8]
//
//        let identity = Identity(name: "Internet Widgits Pty Ltd")
//        let publicKey = identity!.certificate.publicKey!
//        let encryptedData = publicKey.encrypt(data)!
//        
//        
//        let rsaDecryptedData = rsa.decrypt(encryptedData)
//
//        
//        XCTAssert(data == rsaDecryptedData)
//        
//    }
}
