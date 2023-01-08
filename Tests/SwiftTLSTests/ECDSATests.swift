//
//  ECDSATests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 07/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class ECDSATests: XCTestCase {
    static var allTests = [
        ("test_verify_signatureFromSelfSignedECDSACertificate_verifies", test_verify_signatureFromSelfSignedECDSACertificate_verifies),
        ("test_fromPEMFile_withSelfSignedECDSAIdentity_givesPrivateKey", test_fromPEMFile_withSelfSignedECDSAIdentity_givesPrivateKey),
        ("test_verify_signaturefromECDSAPEMFile_verifies", test_verify_signaturefromECDSAPEMFile_verifies),
        ("test_sign_whenSigningSelfSignedECDSACertificate_verifies", test_sign_whenSigningSelfSignedECDSACertificate_verifies),
        ("test_sign_withSecp256r1_verifies", test_sign_withSecp256r1_verifies)
        ]

    override func setUp() {
        var ctx = BigIntContext()
        ctx.open()
//        _ = BigIntContext.setContext(ctx)
    }
    
    override func tearDown() {
//        _ = BigIntContext.setContext(nil)
    }

    func test_verify_signatureFromSelfSignedECDSACertificate_verifies()
    {
        let certificatePath = path(forResource: "Self Signed ECDSA Certificate.cer")
        let data = (try! Data(contentsOf: URL(fileURLWithPath: certificatePath))).UInt8Array()
        
        guard let cert = X509.Certificate(derData: data) else { XCTFail(); return }
        
        let tbsData         = cert.tbsCertificate.DEREncodedCertificate!
        let publicKeyInfo   = cert.tbsCertificate.subjectPublicKeyInfo
        
        let ecdsa = ECDSA(publicKeyInfo: publicKeyInfo)!
        let verified = ecdsa.verify(signature: cert.signatureValue.bits, data: ecdsa.hashAlgorithm.hashFunction(tbsData))
        
        XCTAssertTrue(verified)
    }

    func test_fromPEMFile_withSelfSignedECDSAIdentity_givesPrivateKey() {
        let certificatePath = path(forResource: "ECDSA Identity.pem")
        let ecdsa = ECDSA.fromPEMFile(certificatePath)

        XCTAssert(ecdsa != nil)
    }

    func test_verify_signaturefromECDSAPEMFile_verifies() {
        let pemFile = path(forResource: "ECDSA Identity.pem")
        guard let ecdsa = ECDSA.fromPEMFile(pemFile) else {
            XCTFail()
            return
        }
        
        guard let certificate = X509.Certificate(PEMFile: pemFile) else {
            XCTFail()
            return
        }
        
        let tbsData = certificate.tbsCertificate.DEREncodedCertificate!
        let verified = ecdsa.verify(signature: certificate.signatureValue.bits, data: ecdsa.hashAlgorithm.hashFunction(tbsData))
        
        XCTAssertTrue(verified)
    }

    func test_sign_whenSigningSelfSignedECDSACertificate_verifies() {
        let pemFile = path(forResource: "ECDSA Identity.pem")
        guard let ecdsa = ECDSA.fromPEMFile(pemFile) else {
            XCTFail()
            return
        }
        
        guard let certificate = X509.Certificate(PEMFile: pemFile) else {
            XCTFail()
            return
        }
        
        guard let tbsData = certificate.tbsCertificate.DEREncodedCertificate else {
            XCTFail()
            return
        }
        
        let signatureAlgorithm = certificate.signatureAlgorithm.algorithm
        let hashAlgorithm: HashAlgorithm
        switch signatureAlgorithm
        {
        case .ecdsa(hash: let hash):
            hashAlgorithm = hash
            
        default:
            XCTFail()
            return
        }
        
        let hashedData = hashAlgorithm.hashFunction(tbsData)
        
        var signature: [UInt8] = []
        self.measure {
            signature = try! ecdsa.sign(data: hashedData)
        }
        
        XCTAssert(ecdsa.verify(signature: signature, data: hashedData))
    }
    
    func test_sign_withSecp256r1_verifies() {
        let curve = EllipticCurve.named(.secp256r1)!
        let (privateKey, publicKey) = curve.createKeyPair()
        let ecdsa = ECDSA(curve: curve, publicKey: publicKey, privateKey: privateKey)
        
        let data: [UInt8] = [UInt8]("123456789a123456789a123456789a12".utf8)
        var signature: [UInt8] = []
        self.measure {
            signature = try! ecdsa.sign(data: data)
        }
        
        XCTAssert(ecdsa.verify(signature: signature, data: data))
    }
}
