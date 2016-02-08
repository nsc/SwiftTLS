//
//  EllipticCurveTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 26.12.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class EllipticCurveTests: XCTestCase {

    func test_secp256r1_exists()
    {
        guard EllipticCurve.named(.secp256r1) != nil else { XCTFail(); return }
    }

    func test_secp256r1_isConsistent()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        XCTAssert(curve.G.isOnCurve(curve))
    }

    func test_secp521r1_exists()
    {
        guard EllipticCurve.named(.secp521r1) != nil else { XCTFail(); return }
    }

    func test_secp521r1_isConsistent()
    {
        guard let curve = EllipticCurve.named(.secp521r1) else { XCTFail(); return }

        XCTAssert(curve.G.isOnCurve(curve))
    }

    func test_isOnCurve_G_isCalculatedCorrectly()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        let G = curve.G
        
        XCTAssert(G.isOnCurve(curve))
    }
    
    func test_doublePoint_G_isCalculatedCorrectly()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        let p = curve.doublePoint(curve.G)
        
        XCTAssert(p.isOnCurve(curve))
    }

    func test_addPoints_GAnd4G_isCalculatedCorrectly()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        let G = curve.G
        let p = curve.doublePoint(G)
        let p1 = curve.doublePoint(p)
        let q = curve.addPoints(p, p1)
        
        XCTAssert(q.isOnCurve(curve))
    }

    func test_multiplyPoint_Gtimes2_isCalculatedCorrectly()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        let G = curve.G
        let p = curve.doublePoint(G)
        
        let q = curve.multiplyPoint(G, BigInt(2))
        
        XCTAssert(q.isOnCurve(curve))
        XCTAssert(p == q)
    }

    func test_multiplyPoint_Gtimes4_isCalculatedCorrectly()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        let G = curve.G
        let p = curve.doublePoint(G)
        let p1 = curve.doublePoint(p)
        
        let q = curve.multiplyPoint(G, BigInt(4))
        
        XCTAssert(p1 == q)
    }

    func test_multiplyPoint_withSomeNumber_yieldsPointOnCurve()
    {
        guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
        
        let G = curve.G
        
        for i in 10 ..< 15
        {
            let q = curve.multiplyPoint(G, BigInt(i))
            XCTAssert(q.isOnCurve(curve))
        }
    }
    
    func test_multiplyPoint_onWellKnownCurve_yieldsCorrectResults()
    {
        let a = BigInt(3)
        let b = BigInt(7)
        let p = BigInt(97)
        let G = EllipticCurvePoint(x: BigInt(17), y: BigInt(11))
        let n = BigInt(1)
        let curve = EllipticCurve(p: p, a: a, b: b, G: G, n: n)

        XCTAssert(G.isOnCurve(curve))
        
        // These numbers are generated from a web app from
        // http://andrea.corbellini.name/2015/05/23/elliptic-curve-cryptography-finite-fields-and-discrete-logarithms/
        // (https://cdn.rawgit.com/andreacorbellini/ecc/920b29a/interactive/modk-mul.html )
        let testCases = [
            (2, 54, 69),
            (3, 32, 52),
            (4, 24, 41),
            (5, 13, 20),
            (6, 66, 75),
            (7, 5, 70),
            (8, 50, 30),
            (9, 42, 4),
            (10, 82, 46),
            (100, 17, 11),
            (300, 32, 52)
        ]
        
        for (d, x, y) in testCases
        {
            let result = curve.multiplyPoint(G, BigInt(d))
            
            XCTAssert(result == EllipticCurvePoint(x: BigInt(x), y: BigInt(y)))
        }
    }

    func test_sign_someData_verifies()
    {
        guard let curve = EllipticCurve.named(.secp521r1) else {
            XCTFail()
            return
        }
        
        let (privateKey, publicKey) = curve.createKeyPair()
        
        let ecdsa = ECDSA(curve: curve, publicKey: publicKey, privateKey: privateKey)
        
        let data = [1,2,3,4,5,6,7,8] as [UInt8]
        
        let signature = ecdsa.signData(data)
        
        // use ECDSA only with a public key for verification
        let ecdsa2 = ECDSA(curve: curve, publicKey: publicKey)
        let verified = ecdsa2.verifySignature(signature, data: data)
        
        XCTAssert(verified)
    }
}
