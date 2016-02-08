//
//  ASN1Tests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftTLS

class ASN1Tests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_read_DHParams () {
        let dhParametersPath = NSBundle(forClass: self.dynamicType).URLForResource("dhparams.pem", withExtension: nil)!.path!
        guard let object = ASN1Parser.objectFromPEMFile(dhParametersPath) else {
            XCTFail()
            return
        }
        
        if let sequence = object as? ASN1Sequence {
            XCTAssert(sequence.objects.count == 2)
            
            if let prime = sequence.objects[0] as? ASN1Integer {
                XCTAssert(prime.value.count != 0)
            }
            else {
                XCTFail()
            }
            
            if let generator = sequence.objects[1] as? ASN1Integer {
                XCTAssert(generator.value.count != 0)
            }
            else {
                XCTFail()
            }
        }
    }

    func test_parseObject_withATrueBooleanEncoded_givesCorrectResult() {
        if let boolean = ASN1Parser(data: [0x01, 0x01, 0xff]).parseObject() as? ASN1Boolean {
            XCTAssertTrue(boolean.value)
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withAFalseBooleanEncoded_givesCorrectResult() {
        if let boolean = ASN1Parser(data: [0x01, 0x01, 0x00]).parseObject() as? ASN1Boolean {
            XCTAssertFalse(boolean.value)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_parseObject_withAnOneByteIntegerEncoded_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x02, 0x01, 0x03]).parseObject() as? ASN1Integer {
            XCTAssertTrue(value.value[0] == UInt8(3))
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withAnOneByteBEREncodedEncoded_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x02, 0x81, 0x01, 0x03]).parseObject() as? ASN1Integer {
            XCTAssertTrue(value.value[0] == UInt8(3))
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withDEREncodedBitString1_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 6)
            XCTAssertTrue(value.bitValue[0] == 0b011011100101110111)
            return
        }
        else {
            XCTFail()
        }
    }
    
    func test_parseObject_withDEREncodedBitString2_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x0b, 0x01, 0x27, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x27]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 1)
            var bitValue = value.bitValue
            XCTAssertTrue(bitValue[0] == 0x1391)
            XCTAssertTrue(UInt64(bitValue[1]) == 0x9191919191919193 as UInt64)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_parseObject_withDEREncodedBitString3_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x11, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 0)
            var bitValue = value.bitValue
            XCTAssertTrue(bitValue[0] == 0x123456789abcdef1)
            XCTAssertTrue(bitValue[1] == 0x23456789abcdef12)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_parseObject_withBERConstructedEncodedBitString_givesCorrectResult() {
        if let value = ASN1Parser(data: [0x03, 0x11, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12]).parseObject() as? ASN1BitString {
            XCTAssertTrue(value.unusedBits == 0)
            var bitValue = value.bitValue
            XCTAssertTrue(bitValue[0] == 0x123456789abcdef1)
            XCTAssertTrue(bitValue[1] == 0x23456789abcdef12)
            return
        }
        else {
            XCTFail()
        }
    }

    func test_dataForObject_trueASN1Boolean_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let data = writer.dataFromObject(ASN1Boolean(value: true))
        let object = ASN1Parser(data: data).parseObject()
        
        XCTAssert(object is ASN1Boolean)
        XCTAssert((object as! ASN1Boolean).value == true)
    }

    func test_dataForObject_falseASN1Boolean_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let data = writer.dataFromObject(ASN1Boolean(value: false))
        let object = ASN1Parser(data: data).parseObject()
        
        XCTAssert(object is ASN1Boolean)
        XCTAssert((object as! ASN1Boolean).value == false)
    }

    func test_dataForObject_forSomeASN1Integers_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors : [[UInt8]] = [
            [1],
            [2],
            [1, 2, 3, 4],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            [UInt8](count:1000, repeatedValue: 15)
        ]
        
        for value in testVectors
        {
            let data = writer.dataFromObject(ASN1Integer(value: value))
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1Integer)
            XCTAssert((object as! ASN1Integer).value == value)
        }
    }
    
    func test_dataForObject_ASN1Null_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let data = writer.dataFromObject(ASN1Null())
        let object = ASN1Parser(data: data).parseObject()
        
        XCTAssert(object is ASN1Null)
    }

    func test_dataForObject_ASN1BitStringWithVariousContents_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors = [
            ASN1BitString(unusedBits: 5, data: [0xff, 0xff]),
            ASN1BitString(unusedBits: 1, data: [0xff, 0xff]),
        ]
        
        for bitString in testVectors
        {
            let data = writer.dataFromObject(bitString)
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1BitString)
            XCTAssert(bitString == (object as! ASN1BitString))
        }
    }

    func test_dataForObject_ASN1OctetStringWithVariousContents_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors = [
            ASN1OctetString(data: [1, 2, 3]),
            ASN1OctetString(data: [1, 2, 3, 4, 0x85, 0x86, 0x87, 0x88, 0x89]),
        ]
        
        for octetString in testVectors
        {
            let data = writer.dataFromObject(octetString)
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1OctetString)
            XCTAssert(octetString == (object as! ASN1OctetString))
        }
    }

    func test_dataForObject_ASN1ObjectIdentifierWithVariousContentObjects_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors : [[Int]] = [
            [1,3,14,3,2,26],
            [1,2,840,113549,1,1,1],
            [1,2,840,113549,1,1,11]
        ]
        
        for values in testVectors
        {
            let identifier = ASN1ObjectIdentifier(identifier: values)
            
            let data = writer.dataFromObject(identifier)
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1ObjectIdentifier)
            XCTAssert(identifier == (object as! ASN1ObjectIdentifier))
        }
    }

    func test_dataForObject_ASN1UTF8StringWithVariousContentObjects_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors = [
            ASN1UTF8String(string: "abcdefg"),
            ASN1UTF8String(string: "𐌀𐊡🌃"),
        ]
        
        for value in testVectors
        {
            let data = writer.dataFromObject(value)
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1UTF8String)
            XCTAssert(value == (object as! ASN1UTF8String))
        }
    }

    func test_dataForObject_ASN1SequenceWithVariousContentObjects_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors : [[ASN1Object]] = [
            [ASN1Integer(value:[1])],
            [ASN1Integer(value:[1]), ASN1Integer(value:[2])],
        ]
        
        for values in testVectors
        {
            let sequence = ASN1Sequence(objects: values)
            
            let data = writer.dataFromObject(sequence)
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1Sequence)
            XCTAssert(sequence == (object as! ASN1Sequence))
        }
    }

    func test_dataForObject_ASN1SetWithVariousContentObjects_givesCorrectResult()
    {
        let writer = ASN1Writer()
        
        let testVectors : [[ASN1Object]] = [
            [ASN1Integer(value:[1])],
            [ASN1Integer(value:[1]), ASN1Integer(value:[2])],
        ]
        
        for values in testVectors
        {
            let set = ASN1Set(objects: values)
            
            let data = writer.dataFromObject(set)
            let object = ASN1Parser(data: data).parseObject()
            
            XCTAssert(object is ASN1Set)
            XCTAssert(set == (object as! ASN1Set))
        }
    }
    
    func test_Certificate_fromDEREncodedECDSACertificate_canBeReadCorrectly()
    {
        let certificatePath = NSBundle(forClass: self.dynamicType).pathForResource("Self Signed ECDSA Certificate.cer", ofType: "")!
        let data = NSData(contentsOfFile: certificatePath)!.UInt8Array()

        guard X509.Certificate(DERData: data) != nil else { XCTFail(); return }
    }
    
    func test_Certificate_fromDEREncodedRSACertificate_canBeReadCorrectly()
    {
        let certificatePath = NSBundle(forClass: self.dynamicType).pathForResource("Self Signed RSA Certificate.cer", ofType: "")!
        let data = NSData(contentsOfFile: certificatePath)!.UInt8Array()
        
        guard X509.Certificate(DERData: data) != nil else { XCTFail(); return }
    }
}
