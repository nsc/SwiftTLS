import XCTest

#if !os(macOS)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(AESTests.allTests),
        testCase(ASN1Tests.allTests),
        testCase(BigIntBitOperationTests.allTests),
        testCase(BlockCipherTests.allTests),
        testCase(GaloisFieldTests.allTests),
        testCase(MontgomeryTests.allTests),
        testCase(TLSUtilitiesTests.allTests),
        testCase(TLSTests.allTests),
        testCase(TLSRecordTests.allTests),
        testCase(TLSClientHelloTests.allTests),
        testCase(TLSServerHelloTests.allTests),
        testCase(TLSServerKeyExchangeTests.allTests),
        testCase(TLSCertificateMessageTests.allTests),
        testCase(TLSClientKeyExchangeTests.allTests),
        testCase(TLSEncryptedExtensionsTests.allTests),
        testCase(TLSReadExtensionsTests.allTests),
        testCase(TLSVersionTests.allTests),
        testCase(SocketTests.allTests),
        testCase(EllipticCurveTests.allTests),
        testCase(RSATests.allTests),
        testCase(ECDSATests.allTests),
        testCase(OIDTests.allTests),
        testCase(SHA1Tests.allTests),
        testCase(SHA224Tests.allTests),
        testCase(SHA256Tests.allTests),
        testCase(SHA384Tests.allTests),
        testCase(SHA512Tests.allTests),
    ]
}
#endif
