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
    static var allTests = [
        ("test_sign_someData_verifies", test_sign_someData_verifies),
        ("test_secp256r1_exists", test_secp256r1_exists),
        ("test_secp256r1_isConsistent", test_secp256r1_isConsistent),
        ("test_secp521r1_exists", test_secp521r1_exists),
        ("test_secp521r1_isConsistent", test_secp521r1_isConsistent),
        ("test_isOnCurve_G_isCalculatedCorrectly", test_isOnCurve_G_isCalculatedCorrectly),
        ("test_doublePoint_G_isCalculatedCorrectly", test_doublePoint_G_isCalculatedCorrectly),
        ("test_addPoints_GAnd4G_isCalculatedCorrectly", test_addPoints_GAnd4G_isCalculatedCorrectly),
        ("test_multiplyPoint_Gtimes2_isCalculatedCorrectly", test_multiplyPoint_Gtimes2_isCalculatedCorrectly),
        ("test_multiplyPoint_Gtimes4_isCalculatedCorrectly", test_multiplyPoint_Gtimes4_isCalculatedCorrectly),
        ("test_multiplyPoint_withSomeNumber_yieldsPointOnCurve", test_multiplyPoint_withSomeNumber_yieldsPointOnCurve),
        ("test_multiplyPoint_onWellKnownCurve_yieldsCorrectResults", test_multiplyPoint_onWellKnownCurve_yieldsCorrectResults),
    ]

    override func setUp() {
        var ctx = BigIntContext()
        ctx.open()
        _ = BigIntContext.setContext(ctx)
    }
    
    override func tearDown() {
        _ = BigIntContext.setContext(nil)
    }
    
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
        BigInt.withContext { _ in
            guard let curve = EllipticCurve.named(.secp256r1) else { XCTFail(); return }
            
            let G = curve.G
            let p = curve.doublePoint(G)
            let p1 = curve.doublePoint(p)
            let q = curve.addPoints(p, p1)
            
            XCTAssert(q.isOnCurve(curve))
        }
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
        let curve = EllipticCurve(name: .arbitrary_explicit_prime_curves, p: p, a: a, b: b, G: G, n: n)

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
        BigInt.withContext { _ in
            guard let curve = EllipticCurve.named(.secp256r1) else {
                XCTFail()
                return
            }
            
            let (privateKey, publicKey) = curve.createKeyPair()
            
            let ecdsa = ECDSA(curve: curve, publicKey: publicKey, privateKey: privateKey)
            
            let data = [1,2,3,4,5,6,7,8] as [UInt8]
            
            let signature: (BigInt, BigInt) = ecdsa.sign(data: data)
            
            // use ECDSA only with a public key for verification
            let ecdsa2 = ECDSA(curve: curve, publicKey: publicKey)
            let verified = ecdsa2.verify(signature: signature, data: data)
            
            XCTAssert(verified)
        }
    }
    
    // Using `Release` optimization flags and NOT using `Debug Executable` when running tests yields the following results:
    // On Macbook Pro 2016, 2.9 GHZ, 16 GB 2133 MHZ Ram:
    // Using `measure` closure: Takes real time ~2 minutes, measured time ~11 seconds
    func donttest30Multiplications() {
        let x = ["179E6FA8417E4F52884E2F140AA65702258DDFCED990050CC3206B8DF11BCE93", "44835F6BB10DD83963152DA7AA5B48341BEAD48B0F7CFF68DC361F464D88E73E", "D39B28D6242EB83B8E0DD443A8F68E2BDA889418A99F619EC542A5C5FB02C83D", "C5D878236FEE186AC4A08C3A00D720A0AE34D648A23FBA7C82F8BE598885DC76", "FBA25491A09113D5CA504E866BE80D5C2586AC274DF7BEDC07E890A946868212", "CE5F7A87FFACE77783E588DD6BDB300F245A139EE4261FA2B1E2218A03E8C7DE", "0346BACFC7DDC3ABEEB358A1D3DF530F69853E9011EABE090739638BAC5CD1EA", "393FC2BA7113FE4A5AEFD39C581206228CF68E0F034CC05A1925018DBEDDA20A", "8CA6189711485C7CBB908F4171985092BCC1FAE439F6DC73C816FC3BC0E5B66B", "D4F94F5D934E1B8D7F9DECFA607CE28206D416969C14F732B7A82BC387E4D6F9", "05D6E55643DEA537AC33B1C46D48D754CFE54889304380AD4C7774AC415AAEBD", "6558AA647AE503CC1E936C7A5C1280D74E849932C28FE5CE4634672ADCA03B65", "E9C8BF0B11EC4EE948414B06E92C66EF4F70DD13D31449D37A57FB2496A03770", "E687028184D99BB481557917A4BC30853CB608D60F0612656957AAB2E353513A", "6CE1781C7A99FE68383FEDC24F9201DAA2D1BD1079B099F6BF2EC36B2B0D1C29", "19BF72575758FA65189184466AD093DC62109A7180211F1E1ABB4AC5BC02BD3E", "06511DBF82C92DDC7595D1CB9881FBCA4F63C4982B04C0B3C5044A42CD728BCE", "A516A850FDE964AA090860DC2E07B6C94F784780ECC3FCAD678769F422F863DC", "53E3AAA95577873095074D93404045D3E75C058442941D82B6B20B2E0FCDAEFB", "EA8E8FE207D275D1AF0B11683552CB9BA9A01CD7A8153FFE17D41917C5992A7B", "187C6B75ED141C3ED7A4B55807B3076F3BBB5BEE4A8AC9B00CD79138531E6C4B", "FBF6630B18399FC837B7E272F620590BEFC7C3797C4184E3E956FD8D7A621BF7", "119A4E49478514EA61AEEF122DBD5491D1C4D10FDC7000432D481D36002C8B49", "5D10D858CDB3DB1131AD5E0C863BF73690FC70A6868A56E540B4C31CD545274B", "769F6B38139FF3591D8B98860BA020F8874CA4557C04EBEEA333EDA6E0397DBE", "860C56B3700B1621BBB67E45FC28C36BE80A189FA80E7E0F9598A488A6520CBE", "9EC998C346C6A10A656E14E6DC8CEB476FD05AC2B2B4B3C3035BF4EB5A1DF434", "B9CC16CDA345D80B095B76DB9028948947F6585496ADF989DA3BCE3C5EC64369", "86EA2841BC8A38A0730282349FC908D68E3E6708B4CE7AC7CBE93D2466DC7AC3", "E063B929738980E7DA3EA0A76B2368B261E11AB5529737AD3166B012C00E53EA"]
        
        let y = ["66860DDF8C8E7175BC3FF5791DC6B098C57DCD1D894CE5204B1F99D626C937D2", "FCFEA29FA7DE500AA74DA27077B9CAEAE213AB17C0185C52684E221FCD336E12", "D0BA55F9A0EB503E1C66C3EB85C61B5AF41BB72A0238B936FD3D6A0623BCCF93", "B8CB7A95EBC470DE3C7CE7C6831A13FF9EA787FC0CEFF9F2E1A43183BC42D2C8", "00B8F7A7579B10C532F9FBE30118C0943FD868D7F6F8343BA26BEF9A21CB6724", "AD3D70EA66002BA03AC514270B832072C2C34D92DD9F3D834C93E501AAB857E5", "269967D42036C739A0A25EA9C5A8793B7D99E6A6F8598537DE97B50813855689", "17960EEF12ACACF5D25752423295FA0C54F0628650A1C7F7C491BBC6E9E61C11", "492D1E4068C8BC5220960AD093CD51EAFBCEB09B510E7FE9BE9689AC5F340EF9", "EDC50E06AA5A679502CA1671F053FD36E8D2857AF5FB525F5F7D8A0C0AF17467", "F52FD1644F3B1063E69D99E57D8374D2C5D920E25BA0F3109480A6E483751A0C", "3C79D595B9D8F8B649EABD7EEBC688FC912CF74CB9D34403480D5DC2367006A1", "E2C948F81CB95E10A13CEF7DD36AC38F93DEB62120A95D33124BABDBA75426AD", "1C4CFE00FCB269C6AE46AF073ECB971875704DF7C41189CD50279CAECEEE40E0", "E4A414FC3C953A7892831ABE7E4E31EE70E97240DDBD381C1CCAFAF1227C6B7A", "BD270677B89738BF8C876EC608DB680198ADCC7DEA17EEBDB4C4F9B0D78C4094", "17003217A51B2B61A85B1D7148FB55A5C912B3F25B92B5ED5BEDF6920818643D", "71BB19552CB956E9BA4F9CFC85A4956A691037ED26209758A8C5EA0313B79D2B", "D2A1271C7157A14F394DF9A5E46BEFB9FCBBF3E95E222F7B276D1814247CCE17", "C5423D968AFA153C7B9C52F2386F2083D2BBBCF932A6C37F6072D23396637A04", "2C25A85713A69DDDD197648FDB2F99D423421842A37866CCFAB1BCD46F34C994", "BAFBA637DAE1B5BA6D740FBB4765556C2DDD087B02DB27176D0CE2CD69D6073D", "D8E4E1A85BCBF1B593A5BB74E608625107D7933FB3F222ECA286C4C2CD824F47", "0032B6B2D53D6163AEB32963D669B4CB265C42AC377B699E8B26EEB3E7DF8507", "47B5F25C437B7E631095DD80C2E0962156E08955211A51A5257062E61F0ED157", "B52F4D5FB4902D8FE4C61BFDF89C2CE3700B660474FD2B8E3521C0A3D00A4E87", "7DB059BC1B03800DB422DC10C6D28D401D6A87A7F60737B6C22B75AD93ABBAD6", "97FE73213B0DB81DA304A37CA4BB6587029707A323A4CA5D9E5D0009FC8FA3AD", "7A9144774ACFF165D2BB849820877B4453663E7EF102F7D51D78DBC061597CF1", "36AC7BA226064DEA2D6E59DC9A4A6E2FB45D77AA6513848E67BCA6F9CC4F0AAA"]
        
        func toNumber(_ hex: String) -> BigInt {
            return BigInt(hexString: hex)!
        }
        
        BigInt.withContext { _ in
            
            let xNum = x.map { toNumber($0) }
            let yNum = y.map { toNumber($0) }
            
            let expected = zip(xNum, yNum).map { EllipticCurvePoint(x: $0, y: $1) }
            var calculated = [EllipticCurvePoint]()
            let count = expected.count
            
            let secp256r1Curve = EllipticCurve.named(.secp256r1)!
            self.measure {
                for D in 1...count {
                    BigInt.withContext { _ in
                        let p = secp256r1Curve.multiplyPoint(secp256r1Curve.G, (secp256r1Curve.p - BigInt(D)))
                        calculated.append(p)
                    }
                }
            }
        }
//        for i in 0..<count {
//            XCTAssertEqual(calculated[i], expected[i])
//        }
    }
}
