//
//  ASN1Parser.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

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


class ASN1Object
{
}

class ASN1TaggedObject : ASN1Object
{
    var tag : Int
    var taggedObject : ASN1Object
    init(tag: Int, taggedObject: ASN1Object)
    {
        self.tag = tag
        self.taggedObject = taggedObject
    }
}

class ASN1Boolean : ASN1Object
{
    var value : Bool
    init(value: Bool)
    {
        self.value = value
    }
}

class ASN1Integer : ASN1Object
{
    var value : [UInt8]
    
    init(data : [UInt8])
    {
        self.value = data
    }
}

class ASN1BitString : ASN1Object
{
    var unusedBits : Int
    var value : [UInt8]
    
    init(unusedBits: Int, data : [UInt8])
    {
        self.unusedBits = unusedBits
        self.value = data
    }
}

class ASN1OctetString : ASN1Object
{
    var value : [UInt8]
    
    init(data : [UInt8])
    {
        self.value = data
    }
}

class ASN1Null : ASN1Object
{
}

class ASN1ObjectIdentifier : ASN1Object
{
    var identifier : [Int]
    init(identifier: [Int])
    {
        self.identifier = identifier
    }
}

class ASN1Sequence : ASN1Object
{
    var objects : [ASN1Object]
    
    init(objects : [ASN1Object])
    {
        self.objects = objects
    }
}

class ASN1Set : ASN1Object
{
    var objects : [ASN1Object]
    
    init(objects : [ASN1Object])
    {
        self.objects = objects
    }
}

class ASN1PrintableString : ASN1Object
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
}

class ASN1UTCTime : ASN1Object
{
    var string : String
    init(string: String)
    {
        self.string = string
    }
}

class ASN1Parser
{
    var data : [UInt8]
    var cursor : Int
    
    init(data : [UInt8])
    {
        self.data = data
        self.cursor = 0
    }
    
    init?(PEMFile : String)
    {
        if let base64string = NSString(contentsOfFile: PEMFile, encoding: NSUTF8StringEncoding, error: nil) {
            var range = base64string.rangeOfString("-----BEGIN")
            var rangeOfBase64Block = NSRange()
            if range.location != NSNotFound {
                var eol = base64string.rangeOfString("\n", options: NSStringCompareOptions(0), range: NSRange(location: range.location, length: base64string.length - range.location))
                rangeOfBase64Block.location = eol.location + 1
                
                range = base64string.rangeOfString("-----END",
                    options: NSStringCompareOptions(0),
                    range: NSRange(location: rangeOfBase64Block.location, length: base64string.length - rangeOfBase64Block.location))
                
                if range.location != NSNotFound {
                    rangeOfBase64Block.length = range.location - 1 - rangeOfBase64Block.location
                    
                    var base64 = base64string.substringWithRange(rangeOfBase64Block)
                    if let data = NSData(base64EncodedString:base64, options: .IgnoreUnknownCharacters) {
                        
                        self.data = [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>(data.bytes), count: data.length))
                        self.cursor = 0
                        return
                    }
                }
            }
        }
        
        self.data = []
        self.cursor = 0
        return nil
    }
    
    func _data(var range : Range<Int>) -> [UInt8]? {
        let length = self.data.count
        if  range.startIndex >= 0 &&
            range.startIndex <= length &&
            range.endIndex > range.startIndex &&
            range.endIndex <= length {

                return [UInt8](self.data[range])
        }
        
        return nil
    }
    
    func parseObject() -> ASN1Object?
    {
        var object : ASN1Object? = nil
        if let t = self._data(cursor..<cursor+1) {
            var type = t[0]
            cursor += 1
            
            let constructed = type & ASN1_CONSTRUCTED != 0
            let contextSpecific = (type & ASN1_CLASS_MASK) == ASN1Class.CONTEXT_SPECIFIC.rawValue
            
            type = type & ASN1_LOW_TAG_TYPE_MASK
            
            if let l = self._data(cursor..<cursor+1) {
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
                    if let lengthBytes = self._data(cursor..<cursor + numLengthBytes) {
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
                        return ASN1TaggedObject(tag: Int(type), taggedObject: object)
                    }
                }
                
                if let asn1Type = ASN1TypeTag(rawValue: type)
                {
                    var object : ASN1Object? = nil
                    switch asn1Type
                    {
                    case .BOOLEAN:
                        if let data = self._data(cursor..<cursor + 1) {
                            object = ASN1Boolean(value: data[0] == UInt8(0xff))
                            self.cursor += contentLength
                        }

                    case .INTEGER:
                        if let data = self._data(cursor..<cursor + contentLength) {
                            object = ASN1Integer(data: data)
                            self.cursor += contentLength
                        }

                    case .BITSTRING:
                        if let u = self._data(cursor..<cursor + 1) {
                            let unusedBits = Int(u[0])
                            
                            if let data = self._data(cursor+1..<cursor + contentLength) {
                                object = ASN1BitString(unusedBits:unusedBits, data: data)
                            }
                        }
                        
                        self.cursor += contentLength

                    case .OCTET_STRING:
                        if let data = self._data(cursor..<cursor + contentLength) {
                            object = ASN1OctetString(data: data)
                            self.cursor += contentLength
                        }

                    case .NULL:
                        object = ASN1Null()
                        self.cursor += contentLength
                        
                    case .OBJECT_IDENTIFIER:
                        if let data = self._data(cursor..<cursor + contentLength) {
                            var identifier = [Int]()
                            var v1 = Int(data[0]) % 40
                            var v0 = (Int(data[0]) - v1) / 40
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
                        var end = self.cursor + contentLength
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
                        var end = self.cursor + contentLength
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
                        
                    case .PRINTABLESTRING:
                        if let data = self._data(cursor..<cursor + contentLength) {
                            if let s = NSString(bytes: data, length: data.count, encoding: NSUTF8StringEncoding) {
                                object = ASN1PrintableString(string: s as String)
                            }
                        }
                        self.cursor += contentLength

                        break
                        
                    case .UTCTIME:
                        if let data = self._data(cursor..<cursor + contentLength) {
                            if let s = NSString(bytes: data, length: data.count, encoding: NSUTF8StringEncoding) {
                                object = ASN1UTCTime(string: s as String)
                            }
                        }
                        self.cursor += contentLength
                        
                        break

                    default:
                        object = ASN1Object()
                        self.cursor += contentLength
                        
                        println("Error: unhandled ASN1 tag \(type)")
                    }
                    
                    return object
                }
                else {
                    println("Error: unknown ASN1 tag \(type)")
                    return nil
                }
            }
        }
        
        return nil
    }

}

func ASN1_print_recursive(object: ASN1Object, var depth : Int = 0)
{
    for var i = 0; i < depth; ++i {
        print("    ")
    }
    
    switch object
    {
    case let object as ASN1TaggedObject:
        
        print("[\(object.tag)]")
        ASN1_print_recursive(object.taggedObject, depth: depth + 1)

    case let object as ASN1Boolean:
        println("BOOLEAN " + (object.value ? "true" : "false"))

    case let object as ASN1Integer:
        println("INTEGER (\(hex(object.value)))")

    case let object as ASN1BitString:
        println("BIT STRING (\(hex(object.value)))")

    case let object as ASN1OctetString:
        println("OCTET STRING (\(hex(object.value)))")

    case let object as ASN1Null:
        println("NULL")
        
    case let object as ASN1ObjectIdentifier:
        
        print("OBJECT IDENTIFIER ")
        for var i = 0; i < object.identifier.count; ++i {
            if i != object.identifier.count - 1 {
                print("\(object.identifier[i]).")
            }
            else {
                print("\(object.identifier[i])")
            }
        }
        println()

    case let object as ASN1PrintableString:
        println("PrintableString \(object.string)")

    case let object as ASN1Sequence:
        println("SEQUENCE (\(object.objects.count) objects)")
        for o in object.objects {
            ASN1_print_recursive(o, depth: depth + 1)
        }

    case let object as ASN1Set:
        println("SET (\(object.objects.count) objects)")
        for o in object.objects {
            ASN1_print_recursive(o, depth: depth + 1)
        }

    case let object as ASN1UTCTime:
        println("UTCTIME \(object.string)")
        
    default:
        println()
        break
    }
}