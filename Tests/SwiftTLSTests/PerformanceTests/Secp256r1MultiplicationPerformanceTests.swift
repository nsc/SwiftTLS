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
    // Using `measure` closure: Takes real time ~2 minutes, measured time ~14 seconds
    func test30HighMultiplications() {
        let x = ["6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978", "5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C", "E2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852", "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED", "B01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9", "8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3", "62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393", "EA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0", "CEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F", "3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1", "741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4", "177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01", "54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B", "F0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F", "76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E", "47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E", "1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA", "CB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83", "83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A", "3250FCF686637C7B2E4AC86EB473BCA53A582139F42B1523FD76364E67399E83", "C0DD241A50D48F99FCC7A186A6D44E0763EC90478E1DEF8E36F5C4E950D67AFB", "E91C7239C2640D7D28A3E39D4583FA63C0BC0A5DF64A4FE672E573045CA7896", "DB474918EC62AD7EB652B8B0AF585ABA9B2F394723AB103776E27D7D8C2AA4CB", "3A67E2554B0C0BB685F4F52D8C07FA8441652FC5B76F1B2484A4DC45F200D687", "F5757C012185A599D1F3958B0AE68AA5DFFD3D78E1A2EEE67417001857658331", "184FFA5819D80D51DEBA2FAC4611F378576355BD683E54ABF2E201173B0883D1", "38D86FA55B4FD1586C5F05FAE7ACFC4D36CBDCF7FA62129339246F69C4300E4E", "D6D33ADEFA195B07A7C36DA090853B8CFD8CD1C688B58A41DEDD693D1C784DEF", "409F8DA21AEA236A5F5A1904D0310C1C6192A67D0DA08936319869A8AD0838A3"]

        let y = ["B01CBD1C01E58065711814B583F061E9D431CCA994CEA1313449BF97C840AE0A", "F888AAEE24712FC0D6C26539608BCF244582521AC3167DD661FB4862DD878C2E", "78CB9BF2B6670082C8B4F931E59B5D1327D54FCAC7B047C265864ED85D82AFCD", "1F0EA8A4B39CC339E62011A02579D289B103693D0CF11FFAA3BD3DC0E7B12739", "1F3E82566FB58D83751E40C9407586D9F2FED1002B27F7772E2F44BB025E925B", "17A3EF8ACDC8252B9013F1D20458FC86E3FF0890E381E9420283B7AC7038801D", "8C14E2411FCCE7CA92F9607C590A6FFFAC38C9CD34FBE4DE3AA1E5793E0BFF4B", "52A533416E1627DCB00EA288EE98311F5D12AE0A4418958725ABF595F0F66A81", "D5D8BB358D36031978FEB569B5715F37B28EB0165B217DC017A5DDB5B22FB705", "78799D5CD655517091EDC32262C4B3EFA6F212D7018AE11135CB4455BB50F88C", "6F66DF64333B375EDB37BC505B0B3975F6F2FB26A16776251D07110317D5C8BF", "F88F4B9463C7A024A98C7CAAB7784EAB71146ED4CA45A358E66A00DD32BB7E2C", "9C44A731B1415AA85DBF6E524BF0B18DD911EB3D5E04B20C63BC441D10384027", "A660E43D60BCE8BBDEDE073FA5D183C8E8E15898CAF6FF7E45837D09F2F4C8A", "4A46C11BA6D1D2E1B19A6B1AE069BC19D5C4DE328A4A05C0B81A6321F2FCB0C9", "567A019DCBE0D9F2934F5E4A1EE178DF7A665FFCF0387455F162228DB473AEEF", "55FFA1184A46A8D89DCE7A9A889B717C7E4D7FBCD72A8CC0CD0878008E0E0323", "90E9BA4EA341A246056482026911A58233EE4A4A10B0E08727C4CC6C395BA5D", "A7289EB3DB2610AFA3CA18EFF292931B5B698E92CF05C1FC1C6EAF8AD4313255", "891B64911D08CDCC5195A14629ED48A360DDFD4596DC0AB007DBF5557909BF47", "BD183CBC9982CA6D684CF6F2E281477376832C3DC4A9957DEA21DB5F8E2B73F6", "7D798CD0569AB748BE583239153F9D2725871A841FC15D29F3432E9427351393", "A209A3C3AAF245DEE5DD8CC4471F429281977CCB8A185A51EC7FB9ABCEBF52AA", "7A7EE2C5448BC0D8BC686B9F84F92AD475DB63B97CF5C82DDE249A936B5854AA", "D82F0E77D0E030BDD9250D98E9C504F273E77509CA589E755612E94CFD086CDB", "C6C5912ED3898A4EB4EDC72E2D5F702AF591A1AFF7207BF400ACC2018D97213B", "3F5991D799770CA75B3926F7D934666ABA4213349C0FB6E9DF2DBD3D9F6F9190", "C06C47A4B542F0D980095976F618FDD1074603456E276448606CF23F00961B84", "7B5545E811E6A282C087DBA0AA75A234F65E9955B46A1212AAF3EDBA6C2E4359", "8F23084D30FF71A9F1D918D42C42BF08C1665F14E9D5986C1E9C2D38D5E170A5"]

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
                let p = secp256r1Curve.multiplyPoint(secp256r1Curve.G, (secp256r1Curve.n - BigInt(D)))
                if calculated.count < count {
                    calculated.append(p)
                }
            }
        }
        XCTAssertEqual(calculated.count, count)

        for i in 0..<count {
            XCTAssertEqual(calculated[i], expected[i])
        }
    }
    // Using `Release` optimization flags and NOT using `Debug Executable` when running tests yields the following results:
    // On Macbook Pro 2016, 2.9 GHZ, 16 GB 2133 MHZ Ram:
    // Using `measure` closure: Takes real time ~13 minutes, measured time ~74 seconds
    func test1000LowMultiplications() {
        var calculated = [EllipticCurvePoint]()
        let count = lastTwoCharsInHexRepresentationOfXValueOfPoints.count
        let secp256r1Curve = EllipticCurve.named(.secp256r1)!
        self.measure {
            for D in 1...count {
                let p = secp256r1Curve.multiplyPoint(secp256r1Curve.G, (BigInt(1 + D)))
                if calculated.count < count {
                    calculated.append(p)
                }
            }
        }
        XCTAssertEqual(calculated.count, count)

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

