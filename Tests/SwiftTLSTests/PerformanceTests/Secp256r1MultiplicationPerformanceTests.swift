//
//  Secp256r1MultiplicationPerformanceTests.swift
//  SwiftTLSTests
//
//  Created by Alexander Cyon on 2018-07-18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation
import XCTest

@testable import SwiftTLS

extension EllipticCurvePoint: Equatable {}

class Secp256r1MultiplicationPerformanceTests: XCTestCase {

    // Using `Release` optimization flags and NOT using `Debug Executable` when running tests yields the following results:
    // On Macbook Pro 2016, 2.9 GHZ, 16 GB 2133 MHZ Ram:
    // Using `measure` closure: Takes real time ~2 minutes, measured time ~11 seconds
    func test30HighMultiplications() {
        let x = ["179E6FA8417E4F52884E2F140AA65702258DDFCED990050CC3206B8DF11BCE93", "44835F6BB10DD83963152DA7AA5B48341BEAD48B0F7CFF68DC361F464D88E73E", "D39B28D6242EB83B8E0DD443A8F68E2BDA889418A99F619EC542A5C5FB02C83D", "C5D878236FEE186AC4A08C3A00D720A0AE34D648A23FBA7C82F8BE598885DC76", "FBA25491A09113D5CA504E866BE80D5C2586AC274DF7BEDC07E890A946868212", "CE5F7A87FFACE77783E588DD6BDB300F245A139EE4261FA2B1E2218A03E8C7DE", "0346BACFC7DDC3ABEEB358A1D3DF530F69853E9011EABE090739638BAC5CD1EA", "393FC2BA7113FE4A5AEFD39C581206228CF68E0F034CC05A1925018DBEDDA20A", "8CA6189711485C7CBB908F4171985092BCC1FAE439F6DC73C816FC3BC0E5B66B", "D4F94F5D934E1B8D7F9DECFA607CE28206D416969C14F732B7A82BC387E4D6F9", "05D6E55643DEA537AC33B1C46D48D754CFE54889304380AD4C7774AC415AAEBD", "6558AA647AE503CC1E936C7A5C1280D74E849932C28FE5CE4634672ADCA03B65", "E9C8BF0B11EC4EE948414B06E92C66EF4F70DD13D31449D37A57FB2496A03770", "E687028184D99BB481557917A4BC30853CB608D60F0612656957AAB2E353513A", "6CE1781C7A99FE68383FEDC24F9201DAA2D1BD1079B099F6BF2EC36B2B0D1C29", "19BF72575758FA65189184466AD093DC62109A7180211F1E1ABB4AC5BC02BD3E", "06511DBF82C92DDC7595D1CB9881FBCA4F63C4982B04C0B3C5044A42CD728BCE", "A516A850FDE964AA090860DC2E07B6C94F784780ECC3FCAD678769F422F863DC", "53E3AAA95577873095074D93404045D3E75C058442941D82B6B20B2E0FCDAEFB", "EA8E8FE207D275D1AF0B11683552CB9BA9A01CD7A8153FFE17D41917C5992A7B", "187C6B75ED141C3ED7A4B55807B3076F3BBB5BEE4A8AC9B00CD79138531E6C4B", "FBF6630B18399FC837B7E272F620590BEFC7C3797C4184E3E956FD8D7A621BF7", "119A4E49478514EA61AEEF122DBD5491D1C4D10FDC7000432D481D36002C8B49", "5D10D858CDB3DB1131AD5E0C863BF73690FC70A6868A56E540B4C31CD545274B", "769F6B38139FF3591D8B98860BA020F8874CA4557C04EBEEA333EDA6E0397DBE", "860C56B3700B1621BBB67E45FC28C36BE80A189FA80E7E0F9598A488A6520CBE", "9EC998C346C6A10A656E14E6DC8CEB476FD05AC2B2B4B3C3035BF4EB5A1DF434", "B9CC16CDA345D80B095B76DB9028948947F6585496ADF989DA3BCE3C5EC64369", "86EA2841BC8A38A0730282349FC908D68E3E6708B4CE7AC7CBE93D2466DC7AC3", "E063B929738980E7DA3EA0A76B2368B261E11AB5529737AD3166B012C00E53EA"]

        let y = ["66860DDF8C8E7175BC3FF5791DC6B098C57DCD1D894CE5204B1F99D626C937D2", "FCFEA29FA7DE500AA74DA27077B9CAEAE213AB17C0185C52684E221FCD336E12", "D0BA55F9A0EB503E1C66C3EB85C61B5AF41BB72A0238B936FD3D6A0623BCCF93", "B8CB7A95EBC470DE3C7CE7C6831A13FF9EA787FC0CEFF9F2E1A43183BC42D2C8", "00B8F7A7579B10C532F9FBE30118C0943FD868D7F6F8343BA26BEF9A21CB6724", "AD3D70EA66002BA03AC514270B832072C2C34D92DD9F3D834C93E501AAB857E5", "269967D42036C739A0A25EA9C5A8793B7D99E6A6F8598537DE97B50813855689", "17960EEF12ACACF5D25752423295FA0C54F0628650A1C7F7C491BBC6E9E61C11", "492D1E4068C8BC5220960AD093CD51EAFBCEB09B510E7FE9BE9689AC5F340EF9", "EDC50E06AA5A679502CA1671F053FD36E8D2857AF5FB525F5F7D8A0C0AF17467", "F52FD1644F3B1063E69D99E57D8374D2C5D920E25BA0F3109480A6E483751A0C", "3C79D595B9D8F8B649EABD7EEBC688FC912CF74CB9D34403480D5DC2367006A1", "E2C948F81CB95E10A13CEF7DD36AC38F93DEB62120A95D33124BABDBA75426AD", "1C4CFE00FCB269C6AE46AF073ECB971875704DF7C41189CD50279CAECEEE40E0", "E4A414FC3C953A7892831ABE7E4E31EE70E97240DDBD381C1CCAFAF1227C6B7A", "BD270677B89738BF8C876EC608DB680198ADCC7DEA17EEBDB4C4F9B0D78C4094", "17003217A51B2B61A85B1D7148FB55A5C912B3F25B92B5ED5BEDF6920818643D", "71BB19552CB956E9BA4F9CFC85A4956A691037ED26209758A8C5EA0313B79D2B", "D2A1271C7157A14F394DF9A5E46BEFB9FCBBF3E95E222F7B276D1814247CCE17", "C5423D968AFA153C7B9C52F2386F2083D2BBBCF932A6C37F6072D23396637A04", "2C25A85713A69DDDD197648FDB2F99D423421842A37866CCFAB1BCD46F34C994", "BAFBA637DAE1B5BA6D740FBB4765556C2DDD087B02DB27176D0CE2CD69D6073D", "D8E4E1A85BCBF1B593A5BB74E608625107D7933FB3F222ECA286C4C2CD824F47", "0032B6B2D53D6163AEB32963D669B4CB265C42AC377B699E8B26EEB3E7DF8507", "47B5F25C437B7E631095DD80C2E0962156E08955211A51A5257062E61F0ED157", "B52F4D5FB4902D8FE4C61BFDF89C2CE3700B660474FD2B8E3521C0A3D00A4E87", "7DB059BC1B03800DB422DC10C6D28D401D6A87A7F60737B6C22B75AD93ABBAD6", "97FE73213B0DB81DA304A37CA4BB6587029707A323A4CA5D9E5D0009FC8FA3AD", "7A9144774ACFF165D2BB849820877B4453663E7EF102F7D51D78DBC061597CF1", "36AC7BA226064DEA2D6E59DC9A4A6E2FB45D77AA6513848E67BCA6F9CC4F0AAA"]

        func toNumber(_ hex: String) -> BigInt {
            return BigInt(hexString: hex)!
        }

        let xNum = x.map { toNumber($0) }
        let yNum = y.map { toNumber($0) }

        let expected = zip(xNum, yNum).map { EllipticCurvePoint(x: $0, y: $1) }
        var calculated = [EllipticCurvePoint]()
        let count = expected.count

        let secp256r1Curve = EllipticCurve.named(.secp256r1)!
        self.measure {
            for D in 1...count {
                let p = secp256r1Curve.multiplyPoint(secp256r1Curve.G, (secp256r1Curve.p - BigInt(D)))
                calculated.append(p)
            }
        }

        for i in 0..<count {
            XCTAssertEqual(calculated[i], expected[i])
        }
    }
    // Using `Release` optimization flags and NOT using `Debug Executable` when running tests yields the following results:
    // On Macbook Pro 2016, 2.9 GHZ, 16 GB 2133 MHZ Ram:
    // Using `measure` closure: Takes real time ~11 minutes, measured time ~70 seconds
    func test1000LowMultiplications() {
        var calculated = [EllipticCurvePoint]()
        let count = lastTwoCharsInHexRepresentationOfXValueOfPoints.count
        let secp256r1Curve = EllipticCurve.named(.secp256r1)!
        self.measure {
            for D in 1...count {
                let p = secp256r1Curve.multiplyPoint(secp256r1Curve.G, (BigInt(1 + D)))
                calculated.append(p)
            }
        }

        func lastTwoCharsOfX(_ point: EllipticCurvePoint) -> String {
            return String(point.x.asHexString().suffix(2))
        }

        let twoCharsFromCalculated = calculated.map { point -> String in
            print(point.x.asHexString())
            return lastTwoCharsOfX(point) }
        for i in 0..<count {
            XCTAssertEqual(twoCharsFromCalculated[i], lastTwoCharsInHexRepresentationOfXValueOfPoints[i])
        }
    }

}

extension BigInt {
    func asHexString(uppercased: Bool = true) -> String {
        let hexString = asBigEndianData().toHexString()
        guard uppercased else { return hexString }
        return hexString.uppercased()
    }
}

extension Data {
    public var bytes: Array<UInt8> {
        return Array(self)
    }

    public func toHexString() -> String {
        return bytes.toHexString()
    }
}

extension Array where Element == UInt8 {
    public func toHexString() -> String {
        return `lazy`.reduce("") {
            var s = String($1, radix: 16)
            if s.count == 1 {
                s = "0" + s
            }
            return $0 + s
        }
    }
}

private let lastTwoCharsInHexRepresentationOfXValueOfPoints = ["78", "6C", "52", "ED", "A9", "A3", "93", "E0", "3F", "D1", "C4", "01", "0B", "5F", "6E", "3E", "DA", "83", "9A", "83", "FB", "96", "CB", "87", "31", "D1", "4E", "EF", "A3", "8B", "E1", "93", "9E", "1A", "EF", "48", "46", "C4", "E6", "A2", "0C", "8D", "9B", "03", "F8", "7C", "CA", "55", "A2", "B1", "18", "36", "7D", "A0", "2E", "77", "1D", "45", "63", "0E", "2B", "C1", "85", "10", "7B", "3C", "10", "FE", "97", "69", "3C", "CD", "BF", "4B", "8C", "7B", "B2", "57", "13", "72", "0D", "E8", "07", "8B", "B9", "FC", "C6", "42", "57", "CA", "35", "9D", "E4", "74", "50", "19", "A9", "9C", "70", "AF", "9E", "F6", "0E", "C2", "2C", "7F", "5D", "43", "8F", "9E", "86", "13", "79", "E4", "98", "2D", "5B", "C5", "D8", "69", "58", "39", "8A", "56", "43", "3C", "F6", "D4", "5B", "87", "3D", "27", "AA", "B2", "58", "D2", "1C", "9B", "F5", "38", "DA", "6D", "81", "20", "93", "BF", "63", "89", "1C", "13", "F5", "9E", "AD", "6F", "5F", "96", "93", "52", "E0", "25", "65", "48", "B6", "7B", "93", "42", "C8", "CA", "8D", "FF", "81", "03", "4B", "9B", "5A", "CA", "0F", "5A", "2F", "70", "D9", "86", "45", "2B", "6B", "13", "72", "FD", "A8", "F0", "36", "4C", "F3", "B0", "A1", "88", "D6", "4A", "34", "C7", "1A", "11", "9C", "0C", "19", "18", "FE", "D5", "7D", "5A", "98", "51", "53", "9B", "3A", "4B", "FC", "CF", "C0", "79", "83", "69", "4D", "DA", "83", "03", "AA", "BC", "30", "2F", "6D", "9A", "BB", "1A", "1E", "80", "8C", "68", "EF", "D1", "9C", "29", "A5", "B3", "86", "0A", "92", "4F", "B9", "BB", "AE", "CF", "D3", "14", "1B", "DE", "D2", "38", "45", "FD", "B1", "4A", "78", "66", "F4", "82", "55", "17", "5B", "85", "9A", "00", "7F", "09", "B0", "40", "7F", "1B", "C3", "ED", "19", "94", "6F", "F8", "05", "DB", "FF", "B2", "D1", "60", "7C", "F9", "2B", "77", "55", "38", "94", "C5", "69", "9D", "F6", "A7", "57", "9D", "9D", "8A", "01", "FB", "2E", "CF", "52", "3A", "C5", "34", "19", "F2", "0B", "83", "C8", "1A", "24", "3D", "24", "BD", "99", "8E", "CA", "3B", "82", "E8", "9D", "71", "DB", "56", "42", "3A", "94", "D6", "FA", "70", "08", "2E", "11", "E9", "BC", "1E", "F3", "B0", "D3", "A2", "5B", "F4", "3E", "0C", "AA", "5E", "67", "9A", "94", "EC", "E1", "D8", "C7", "1E", "52", "27", "6B", "59", "4A", "03", "FB", "87", "C3", "8C", "D8", "0F", "C2", "0A", "65", "BB", "81", "D6", "D8", "66", "41", "A4", "F8", "72", "74", "EB", "30", "3B", "F8", "B9", "25", "CF", "32", "E2", "1D", "22", "F5", "01", "93", "82", "88", "42", "F9", "B0", "14", "E6", "7F", "06", "CF", "40", "F5", "69", "F6", "28", "C8", "F1", "A3", "6A", "34", "DA", "DA", "11", "B4", "58", "96", "3C", "8C", "6B", "86", "6F", "72", "84", "B9", "0F", "F1", "80", "FA", "5C", "52", "BE", "5F", "2B", "9D", "4F", "D4", "1B", "15", "36", "E4", "32", "07", "58", "5A", "80", "B8", "39", "4E", "E2", "1D", "F4", "BD", "5E", "B9", "E0", "A0", "C9", "8D", "55", "D5", "C8", "CB", "C5", "B4", "1B", "AA", "FD", "49", "A2", "88", "C8", "10", "38", "29", "32", "82", "88", "97", "FD", "4C", "DF", "CD", "EE", "A6", "C7", "71", "F9", "BF", "F6", "3B", "DE", "90", "1B", "BD", "4A", "CB", "B6", "DE", "DF", "3C", "FB", "BF", "31", "7C", "93", "1E", "08", "80", "9E", "D4", "93", "DE", "DF", "C9", "66", "05", "5A", "47", "04", "03", "E6", "C1", "6B", "1B", "C6", "5C", "E8", "D1", "5C", "60", "64", "EB", "46", "8E", "CA", "B3", "DD", "F3", "A7", "A0", "18", "73", "95", "04", "E5", "C6", "E4", "27", "FE", "47", "82", "C0", "00", "18", "49", "C7", "15", "F6", "D1", "0C", "4C", "96", "0B", "6E", "86", "64", "7C", "BB", "CD", "4B", "8F", "9C", "1F", "48", "3D", "2F", "7F", "1C", "88", "0F", "CD", "85", "78", "53", "72", "09", "12", "FA", "AE", "18", "D8", "99", "73", "00", "58", "DE", "0A", "11", "F6", "D8", "B9", "4B", "66", "DE", "28", "CA", "4C", "A6", "E3", "83", "6C", "81", "A8", "5D", "06", "A7", "F1", "FE", "B8", "1D", "53", "E8", "97", "CF", "38", "C5", "54", "0A", "0D", "4B", "A3", "3D", "51", "4D", "E9", "2D", "EB", "FA", "5C", "57", "B5", "1C", "A7", "E0", "0F", "25", "9C", "8C", "FF", "A2", "40", "6C", "8C", "28", "4A", "3B", "6A", "77", "DA", "D6", "3C", "0D", "C1", "97", "1B", "67", "DC", "AB", "5C", "B5", "D1", "AE", "37", "A1", "A5", "0D", "31", "DF", "61", "54", "8F", "5B", "0C", "AD", "C0", "21", "39", "58", "29", "0D", "FF", "FE", "52", "A5", "6A", "84", "8E", "98", "70", "33", "09", "3A", "82", "5D", "FF", "27", "08", "A1", "21", "AD", "B4", "0C", "DB", "22", "CF", "84", "71", "AF", "85", "14", "9B", "C6", "54", "58", "FA", "06", "69", "EE", "90", "6F", "C9", "60", "02", "07", "D4", "84", "55", "4C", "55", "85", "49", "30", "3A", "D3", "8C", "10", "EB", "B3", "CC", "35", "C8", "A7", "75", "24", "E1", "60", "C1", "43", "84", "F2", "C8", "5F", "8F", "72", "43", "FA", "1E", "3F", "EE", "AE", "EC", "2A", "F3", "14", "B6", "19", "CA", "70", "F6", "70", "12", "A3", "3A", "1E", "51", "B6", "C0", "3F", "C5", "AF", "D9", "EC", "A2", "ED", "EE", "5E", "37", "C6", "A2", "EA", "E9", "64", "47", "07", "73", "7E", "89", "AD", "15", "B9", "62", "20", "F4", "4C", "2A", "2B", "E2", "15", "A2", "51", "CD", "23", "EE", "DE", "81", "EE", "07", "B8", "4A", "F8", "18", "10", "DD", "CF", "79", "6C", "CC", "92", "A9", "E1", "85", "0E", "82", "8C", "43", "71", "FE", "51", "1C", "8A", "3C", "44", "C1", "80", "3B", "5C", "A7", "3C", "20", "03", "A6", "76", "70", "5C", "22", "17", "9C", "9A", "49", "90", "3E", "9C", "07", "5E", "84", "33", "CA", "BA", "DB", "7A", "32", "0F", "CE", "2A", "AA", "A2", "9C", "32", "F3", "4A", "44", "8D", "1B", "29", "01", "9C", "D0", "BA", "AB", "6F", "42", "AA", "6E", "DE", "33", "3C", "97", "6C", "0B", "4A", "44", "AD", "8B", "44", "E0", "75", "84", "F0", "01", "C3", "E6", "D3", "06", "27", "97", "EE", "08", "A5", "D8", "A1", "CC", "4B", "44", "49", "98", "56", "3E", "58", "BC", "6E", "2E", "74", "24", "C4", "9C", "22", "32", "26", "C4", "9C", "BD", "C0", "56", "29", "4B", "EC", "80", "49", "BA", "5F", "C5", "6B", "33", "BB", "38", "BD", "B1", "42", "E2", "BD", "77", "BC", "CC", "65", "2C", "54", "C3", "93", "3D", "4E", "A5", "A3", "92", "25", "7E", "02", "C6"]

