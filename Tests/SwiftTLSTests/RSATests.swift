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
    static var allTests = [
        ("test_RSA_PSS_sign_someData_verifies", test_RSA_PSS_sign_someData_verifies),
        ("test_verify_signatureFromSelfSignedRSAPSSCertificate_verifies", test_verify_signatureFromSelfSignedRSAPSSCertificate_verifies),
        ("test_verify_signatureFromSelfSignedRSACertificate_verifies", test_verify_signatureFromSelfSignedRSACertificate_verifies),
        ("test_sign_someData_verifies", test_sign_someData_verifies),
        ("test_decrypt_encryptedData_givesOriginalData", test_decrypt_encryptedData_givesOriginalData),
    ]
    
    func test_sign_someData_verifies()
    {
        let certificatePath = path(forResource: "mycert.pem")

        guard var rsa = RSA.fromPEMFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let signatureAlgorithm = X509.SignatureAlgorithm.rsa_pkcs1(hash: .sha1)
        rsa.signatureAlgorithm = signatureAlgorithm
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = try! rsa.sign(data: data)
        
        print(signature)
        
        var rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        rsa2.signatureAlgorithm = signatureAlgorithm
        let verified = try! rsa2.verify(signature: signature, data: data)
        
        XCTAssert(verified)
    }

    func test_decrypt_encryptedData_givesOriginalData()
    {
        let certificatePath = path(forResource: "mycert.pem")
        
        guard let rsa = RSA.fromPEMFile(certificatePath) else {
            XCTFail()
            return
        }
        
        do {
            let data = [1,2,3,4,5,6,7,8] as [UInt8]
            let rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
            let encrypted = try rsa2.encrypt(data)
            print(encrypted)
            
            let decrypted = try rsa.decrypt(encrypted)
            print(decrypted)
            
            XCTAssert(data == decrypted)
        } catch {
            XCTFail()
        }
    }

    func test_verify_signatureFromSelfSignedRSAPSSCertificate_verifies() {
        let certificatePath = path(forResource: "Self Signed RSA-PSS SHA-256.pem")
        guard let cert = X509.Certificate(PEMFile: certificatePath) else { XCTFail(); return }
        
        let tbsData     = cert.tbsCertificate.DEREncodedCertificate!
        let publicKey   = cert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
        XCTAssert(publicKey.numberOfBits == publicKey.bits.count * 8)
        
        let rsa         = RSA(certificate: cert)
        
        let verified = try! rsa!.verify(signature: cert.signatureValue.bits, data: tbsData)
        
        XCTAssert(verified)
    }
    
    func test_verify_signatureFromSelfSignedRSACertificate_verifies()
    {
        let certificatePath = path(forResource: "Self Signed RSA SHA-256.cer")
        let data = (try! Data(contentsOf: URL(fileURLWithPath: certificatePath))).UInt8Array()
        
        guard let cert = X509.Certificate(derData: data) else { XCTFail(); return }
        
        let tbsData     = cert.tbsCertificate.DEREncodedCertificate!
        let publicKey   = cert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
        XCTAssert(publicKey.numberOfBits == publicKey.bits.count * 8)
        
        let rsa         = RSA(certificate: cert)
        
        let verified = try! rsa!.verify(signature: cert.signatureValue.bits, data: tbsData)

        XCTAssert(verified)
    }
    
    func test_RSA_PSS_sign_someData_verifies()
    {
        let certificatePath = path(forResource: "mycert.pem")
        
        guard var rsa = RSA.fromPEMFile(certificatePath) else {
            XCTFail()
            return
        }
        
        let signatureAlgorithm = X509.SignatureAlgorithm.rsassa_pss(hash: .sha256, saltLength: 64)
        rsa.signatureAlgorithm = signatureAlgorithm

        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = try! rsa.rsassa_pss_sign(message: data)
        
        print(signature)
        
        var rsa2 = RSA(n: rsa.n, publicExponent: rsa.e)
        rsa2.signatureAlgorithm = signatureAlgorithm

        let verified = try! rsa2.rsassa_pss_verify(message: data, signature: signature)
        
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
