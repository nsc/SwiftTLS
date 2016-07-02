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

    func test_verify_signatureFromSelfSignedECDSACertificate_verifies()
    {
        let certificatePath = Bundle(for: self.dynamicType).pathForResource("Self Signed ECDSA Certificate.cer", ofType: "")!
        let data = (try! Data(contentsOf: URL(fileURLWithPath: certificatePath))).UInt8Array()
        
        guard let cert = X509.Certificate(derData: data) else { XCTFail(); return }
        
        let tbsData         = cert.tbsCertificate.DEREncodedCertificate!
        let publicKeyInfo   = cert.tbsCertificate.subjectPublicKeyInfo
        
        let ecdsa = ECDSA(publicKeyInfo: publicKeyInfo)!
        cert.signatureAlgorithm
        let verified = ecdsa.verify(signature: cert.signatureValue.bits, data: Hash_SHA256(tbsData))
        
        XCTAssertTrue(verified)
    }

}
