//
//  ASN1Parser.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftHelper

enum ASN1TypeTag : UInt8
{
    case BOOLEAN                    = 0x01
    case INTEGER                    = 0x02
    case BITSTRING                  = 0x03
    case OCTET_STRING               = 0x04
    case NULL                       = 0x05
    case OBJECT_IDENTIFIER          = 0x06
    case OBJECT_DESCRIPTOR          = 0x07
    case EXTERNAL                   = 0x08
    case REAL                       = 0x09
    case ENUMERATED                 = 0x0a
    case UTF8STRING                 = 0x0c
    case SEQUENCE                   = 0x10
    case SET                        = 0x11
    case NUMERICSTRING              = 0x12
    case PRINTABLESTRING            = 0x13
    case T61STRING                  = 0x14
    case IA5STRING                  = 0x16
    case UTCTIME                    = 0x17
    case GENERALIZEDTIME            = 0x18
    case GRAPHICSTRING              = 0x19
    case GENERALSTRING              = 0x1b
}

let ASN1_CONSTRUCTED : UInt8        = 0x20
let ASN1_LOW_TAG_TYPE_MASK : UInt8  = 0x1f
let ASN1_CLASS_MASK : UInt8         = 0xc0

enum ASN1Class : UInt8
{
    case UNIVERSAL                  = 0x00
    case APPLICATION                = 0x40
    case CONTEXT_SPECIFIC           = 0x80
    case PRIVATE                    = 0xc0
}


public class ASN1Object : Equatable
{
    var underlyingData : [UInt8]?
    private func isEqualTo(_ other : ASN1Object) -> Bool
    {
        return false
    }
}

public func ==(lhs : ASN1Object, rhs : ASN1Object) -> Bool
{
    return lhs.isEqualTo(rhs)
}

class ASN1TaggedObject : ASN1Object
{
    var tag : Int
    var object : ASN1Object
    init(tag: Int, object: ASN1Object)
    {
        self.tag = tag
        self.object = object
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1TaggedObject else {
            return false
        }
        
        return (self.tag == other.tag && self.object == other.object)
    }
}


class ASN1Boolean : ASN1Object
{
    var value : Bool
    init(value: Bool)
    {
        self.value = value
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1Boolean else {
            return false
        }
        
        return self.value == other.value
    }
}

class ASN1Integer : ASN1Object
{
    var value : [UInt8]
    
    init(value : [UInt8])
    {
        self.value = value
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1Integer else {
            return false
        }
        
        return self.value == other.value
    }
}

class ASN1BitString : ASN1Object
{
    var unusedBits : Int
    var value : [UInt8]
    
    var bitValue : [UInt] {
        let size = sizeof(UInt.self)
        var values : [UInt] = []
        
        let unusedBits : UInt = UInt(self.unusedBits)
        let lowerBitsMask : UInt = (1 << unusedBits) - 1
        let numValues = self.value.count
        var v : UInt = 0
        let lengthOfMostSignificantValueInBytes = self.value.count % size
        
        for i in 0 ..< numValues {
            let b = UInt(self.value[i])
            v += b >> unusedBits
            
            if (i + 1) % size == lengthOfMostSignificantValueInBytes {
                values.append(v)
                v = 0
            }
            v = v << 8
            v += (b & lowerBitsMask) << (8 - unusedBits)
        }

        if numValues % size != lengthOfMostSignificantValueInBytes {
            values.append(v)
        }
        
        return values
    }
    
    init(unusedBits: Int, data : [UInt8])
    {
        self.unusedBits = unusedBits
        if unusedBits == 0 {
            self.value = data
        }
        else {
            let mask : UInt8 = 0xff - (UInt8(1 << unusedBits) - 1)
            self.value = data[0 ..< (data.count - 1)] + [data[data.count - 1] & mask]
        }
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1BitString else {
            return false
        }
        
        return self.unusedBits == other.unusedBits && self.value == other.value
    }
}

class ASN1OctetString : ASN1Object
{
    var value : [UInt8]
    
    init(data : [UInt8])
    {
        self.value = data
    }

    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1OctetString else {
            return false
        }
        
        return self.value == other.value
    }
}

class ASN1Null : ASN1Object
{
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        return other is ASN1Null
    }
}

class ASN1ObjectIdentifier : ASN1Object
{
    var identifier : [Int]
    init(identifier: [Int])
    {
        self.identifier = identifier
    }

    init(oid: OID)
    {
        self.identifier = oid.identifier
    }

    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1ObjectIdentifier else {
            return false
        }
        
        return self.identifier == other.identifier
    }
}

class ASN1Sequence : ASN1Object
{
    var objects : [ASN1Object]
    
    init(objects : [ASN1Object])
    {
        self.objects = objects
    }

    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1Sequence else {
            return false
        }

        return self.objects == other.objects
    }
}

class ASN1Set : ASN1Object
{
    var objects : [ASN1Object]
    
    init(objects : [ASN1Object])
    {
        self.objects = objects
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1Set else {
            return false
        }
        
        return self.objects == other.objects
    }
}

public protocol ASN1String : CustomStringConvertible {
    var string : String { get }
}

public extension ASN1String {
    var description : String {
        get {
            return "\(self.dynamicType) \(self.string)"
        }
    }
}

class ASN1UTF8String : ASN1Object, ASN1String
{
    var string : String
    init(string: String)
    {
        self.string = string
    }

    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1UTF8String else {
            return false
        }
        
        return self.string == other.string
    }
}

class ASN1PrintableString : ASN1Object, ASN1String
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1PrintableString else {
            return false
        }
        
        return self.string == other.string
    }
}

class ASN1T61String : ASN1Object, ASN1String
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1T61String else {
            return false
        }
        
        return self.string == other.string
    }
}

class ASN1IA5String : ASN1Object, ASN1String
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1IA5String else {
            return false
        }
        
        return self.string == other.string
    }
}

class ASN1GraphicString : ASN1Object, ASN1String
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1GraphicString else {
            return false
        }
        
        return self.string == other.string
    }
}

class ASN1GeneralString : ASN1Object, ASN1String
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1GeneralString else {
            return false
        }
        
        return self.string == other.string
    }
}

protocol ASN1Time {
    var string : String { get }
}

class ASN1UTCTime : ASN1Object, ASN1Time
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1UTCTime else {
            return false
        }
        
        return self.string == other.string
    }
}

class ASN1GeneralizedTime : ASN1Object, ASN1Time
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
    
    private override func isEqualTo(_ other : ASN1Object) -> Bool
    {
        guard let other = other as? ASN1GeneralizedTime else {
            return false
        }
        
        return self.string == other.string
    }
}

public class ASN1Parser
{
    var data : [UInt8]
    var cursor : Int
    
    public init(data : [UInt8])
    {
        self.data = data
        self.cursor = 0
    }
    
    public convenience init(data : Data)
    {
        self.init(data: [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>((data as NSData).bytes), count: data.count)))
    }
    
    public class func objectFromPEMFile(_ PEMFile : String) -> ASN1Object?
    {
        let sections = self.sectionsFromPEMFile(PEMFile)
        
        guard sections.count == 1 else {
            return nil
        }
        
        return sections.values.first
    }
    
    public class func sectionsFromPEMFile(_ PEMFile : String) -> [String : ASN1Object]
    {
        var sectionDictionary : [String : ASN1Object] = [:]
        do {
            let base64string = try String(contentsOfFile: PEMFile, encoding: String.Encoding.utf8)
            
            for (sectionName, base64) in base64Blocks(with: base64string) {
                // FIXME: the option here is obviously bullshit, but currently Data has only a bogus
                // constructor taking encoding options instead of decoding options and this is the numerical
                // equivalent, i.e. the raw value is 0
                if let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) {
                    
                    data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> () in
                        let parser = ASN1Parser(data: [UInt8](UnsafeBufferPointer<UInt8>(start: bytes, count: data.count)))
                        guard let object = parser.parseObject() else {
                            return
                        }
                        
                        sectionDictionary[sectionName] = object
                        
                        return
                    }
                }
            }
        } catch let error {
            print("Error: \(error)")
        }
    
        return sectionDictionary
    }

    func subData(_ range : Range<Int>) -> [UInt8]? {
        let length = self.data.count
        
        if  0..<length ~= range.lowerBound &&
            range.upperBound <= length {

                return [UInt8](self.data[range])
        }
        
        return nil
    }
    
    public func parseObject() -> ASN1Object?
    {
        let startCursor = cursor
        
        if let t = self.subData(cursor..<cursor+1) {
            var type = t[0]
            cursor += 1
            
//            let constructed = type & ASN1_CONSTRUCTED != 0
            let contextSpecific = (type & ASN1_CLASS_MASK) == ASN1Class.CONTEXT_SPECIFIC.rawValue
            
            type = type & ASN1_LOW_TAG_TYPE_MASK
            
            if let l = self.subData(cursor..<cursor+1) {
                var contentLength = Int(l[0])
                cursor += 1
        
                if contentLength & 0x80 != 0
                {
                    let numLengthBytes = Int(contentLength & 0x7f)
                    if numLengthBytes > 8
                    {
                        fatalError("Error: ASN1 content length larger than 64 bit is not supported")
                    }
                    
                    contentLength = 0
                    if let lengthBytes = self.subData(cursor..<cursor + numLengthBytes) {
                        for b in lengthBytes
                        {
                            contentLength = contentLength << 8 + Int(b)
                        }
                        cursor += numLengthBytes
                    }
                }
                
                if contextSpecific {
//                    self.cursor += contentLength
                    if let object = parseObject() {
                        return ASN1TaggedObject(tag: Int(type), object: object)
                    }
                }
                
                if let asn1Type = ASN1TypeTag(rawValue: type)
                {
                    var object : ASN1Object? = nil
                    switch asn1Type
                    {
                    case .BOOLEAN:
                        if let data = self.subData(cursor..<cursor + 1) {
                            object = ASN1Boolean(value: data[0] == UInt8(0xff))
                            self.cursor += contentLength
                        }

                    case .INTEGER:
                        if let data = self.subData(cursor..<cursor + contentLength) {
                            object = ASN1Integer(value: [UInt8](data))
                            self.cursor += contentLength
                        }

                    case .BITSTRING:
                        if let u = self.subData(cursor..<cursor + 1) {
                            let unusedBits = Int(u[0])
                            
                            if let data = self.subData(cursor+1..<cursor + contentLength) {
                                object = ASN1BitString(unusedBits:unusedBits, data: [UInt8](data))
                            }
                        }
                        
                        self.cursor += contentLength

                    case .OCTET_STRING:
                        if let data = self.subData(cursor..<cursor + contentLength) {
                            object = ASN1OctetString(data: [UInt8](data))
                            self.cursor += contentLength
                        }

                    case .NULL:
                        object = ASN1Null()
                        self.cursor += contentLength
                        
                    case .OBJECT_IDENTIFIER:
                        if let data = self.subData(cursor..<cursor + contentLength) {
                            var identifier = [Int]()
                            let v1 = Int(data[0]) % 40
                            let v0 = (Int(data[0]) - v1) / 40
                            identifier.append(v0)
                            identifier.append(v1)
                            
                            var value = 0
                            for b in data[1..<data.count] {
                                if b & 0x80 == 0 {
                                    value = value << 7 + Int(b)
                                    identifier.append(value)
                                    value = 0
                                }
                                else {
                                    value = value << 7 + Int(b & 0x7f)
                                }
                            }
                            
                            object = ASN1ObjectIdentifier(identifier: identifier)
                            self.cursor += contentLength
                        }
                        
                    case .SEQUENCE:
                        var objects : [ASN1Object] = []
                        let end = self.cursor + contentLength
                        while true {
                            if self.cursor == end {
                                break
                            }
                            if let object = parseObject()
                            {
                                objects.append(object)
                            }
                            else {
                                break
                            }
                        }
                        object = ASN1Sequence(objects: objects)
                     
                    case .SET:
                        var objects : [ASN1Object] = []
                        let end = self.cursor + contentLength
                        while true {
                            if self.cursor == end {
                                break
                            }
                            if let object = parseObject()
                            {
                                objects.append(object)
                            }
                            else {
                                break
                            }
                        }
                        object = ASN1Set(objects: objects)

                        break
                        
                    case .PRINTABLESTRING, .UTF8STRING, .T61STRING, .IA5STRING, .GRAPHICSTRING, .GENERALSTRING:
                        if let data = self.subData(cursor..<cursor + contentLength) {
                            if let s = String.fromUTF8Bytes([UInt8](data)) {
                                switch asn1Type
                                {
                                case .UTF8STRING:
                                    object = ASN1UTF8String(string: s as String)
                                
                                case .PRINTABLESTRING:
                                    object = ASN1PrintableString(string: s as String)
                                
                                case .T61STRING:
                                    object = ASN1T61String(string: s as String)

                                case .IA5STRING:
                                    object = ASN1IA5String(string: s as String)

                                case .GRAPHICSTRING:
                                    object = ASN1GraphicString(string: s as String)

                                case .GENERALSTRING:
                                    object = ASN1GeneralString(string: s as String)

                                default:
                                    break
                                }
                            }
                        }
                        self.cursor += contentLength

                        break
                        
                    case .UTCTIME, .GENERALIZEDTIME:
                        if let data = self.subData(cursor..<cursor + contentLength) {
                            if let s = String.fromUTF8Bytes([UInt8](data)) {
                                switch asn1Type
                                {
                                case .UTCTIME:
                                    object = ASN1UTCTime(string: s as String)
                                
                                case .GENERALIZEDTIME:
                                    object = ASN1GeneralizedTime(string: s as String)
                                    
                                default:
                                    break
                                }
                            }
                        }
                        self.cursor += contentLength
                        
                        break

                    default:
                        object = ASN1Object()
                        self.cursor += contentLength
                        
                        print("Error: unhandled ASN1 tag \(type)")
                    }
                    
                    object?.underlyingData = subData(startCursor..<self.cursor)
                    
                    return object
                }
                else {
                    print("Error: unknown ASN1 tag \(type)")
                    return nil
                }
            }
        }
        
        return nil
    }

}

public func ASN1_printObject(_ object: ASN1Object, depth : Int = 0)
{
    for _ in 0 ..< depth {
        print("    ", terminator: "")
    }
    
    switch object
    {
    case let object as ASN1TaggedObject:
        
        print("[\(object.tag)]", terminator: "")
        ASN1_printObject(object.object, depth: depth + 1)

    case let object as ASN1Boolean:
        print("BOOLEAN " + (object.value ? "true" : "false"))

    case let object as ASN1Integer:
        print("INTEGER (\(hex(object.value)))")

    case let object as ASN1BitString:
        print("BIT STRING (\(hex(object.value)))")

    case let object as ASN1OctetString:
        print("OCTET STRING (\(hex(object.value)))")

    case _ as ASN1Null:
        print("NULL")
        
    case let object as ASN1ObjectIdentifier:
        
        print("OBJECT IDENTIFIER ", terminator: "")
        if let oid = OID(id: object.identifier) {
            print("\(oid) ", terminator: "")
        }
        for i in 0 ..< object.identifier.count {
            if i != object.identifier.count - 1 {
                print("\(object.identifier[i]).", terminator: "")
            }
            else {
                print("\(object.identifier[i])", terminator: "")
            }
        }

        print("")

    case let object as ASN1String:
        print("\(object.dynamicType) \(object.string)")

    case let object as ASN1Sequence:
        print("SEQUENCE (\(object.objects.count) objects)")
        for o in object.objects {
            ASN1_printObject(o, depth: depth + 1)
        }

    case let object as ASN1Set:
        print("SET (\(object.objects.count) objects)")
        for o in object.objects {
            ASN1_printObject(o, depth: depth + 1)
        }

    case let object as ASN1Time:
        print("\(object.dynamicType) \(object.string)")
        
    case _ as ASN1Object:
        print("Unhandled \(object)")
        
    default:
        print("")
        break
    }
}

func base64Blocks(with base64String : String) -> [String:String]
{
    var base64String = base64String
    
    var result = [String:String]()
    
    let beginRegEx = try! RegularExpression(pattern: "-----BEGIN (.*)-----\\R")
    let endRegEx = try! RegularExpression(pattern: "-----END (.*)-----\\R")
    
    while true {
        guard let beginMatch = beginRegEx.firstMatch(in: base64String, options: [], range: NSMakeRange(0, base64String.utf8.count)) else {
            break
        }
        
        let beginRange = beginMatch.range
        let nameRange = beginMatch.range(at: 1)
        
        let name = (base64String as NSString).substring(with: nameRange)
        guard let endMatch = endRegEx.firstMatch(in: base64String, options: [], range: NSMakeRange(0, base64String.utf8.count)) else {
            break
        }
        
        let end = endMatch.range
        
        let base64Block = (base64String as NSString).substring(with: NSMakeRange(beginRange.location + beginRange.length, end.location - (beginRange.location + beginRange.length)))
        
        result[name] = base64Block
        
        base64String = (base64String as NSString).substring(from: end.location + end.length)
    }
    
    return result
}

