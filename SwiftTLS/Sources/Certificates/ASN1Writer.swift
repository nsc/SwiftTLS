//
//  ASN1Writer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05.01.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

func highestBit(_ n : Int) -> Int
{
    var n = n
    
    n |= (n >>  1)
    n |= (n >>  2)
    n |= (n >>  4)
    n |= (n >>  8)
    n |= (n >> 16)
    n |= (n >> 32)
    
    return n - (n >> 1)
}

public class ASN1Writer
{
    private func dataForContentLength(_ contentLength : Int) -> [UInt8]
    {
        if contentLength < 0x80 {
            return [UInt8(contentLength)]
        }
        else {
            let n = Int(log2(Double(highestBit(contentLength))))
            let numberOfBytes = (n + 7) / 8

            var data : [UInt8] = []
            var mask = 0xff << ((numberOfBytes - 1) * 8)
            for i in 0 ..< numberOfBytes
            {
                let v = (contentLength & mask) >> ((numberOfBytes - i - 1) * 8)
                data.append(UInt8(v))
                mask = mask >> 8
            }
            
            return [UInt8(0x80 + numberOfBytes)] + data
        }
    }
    
    private func dataForObjectType(_ type : ASN1TypeTag, content : [UInt8]) -> [UInt8]
    {
        let constructed : Bool
        switch type
        {
        case .SEQUENCE, .SET:
            constructed = true
            
        default:
            constructed = false
        }
        
        return [type.rawValue | (constructed ? ASN1_CONSTRUCTED : 0)] + dataForContentLength(content.count) + content
    }
    
    func dataFromObject(_ object : ASN1Object) -> [UInt8]
    {
        switch object
        {
//        case let object as ASN1TaggedObject:
//            break
            
        case let object as ASN1Boolean:
            return [ASN1TypeTag.BOOLEAN.rawValue, 0x01, object.value ? 0xff : 0x00]
            
        case let object as ASN1Integer:
            return dataForObjectType(ASN1TypeTag.INTEGER, content: object.value)

        case let object as ASN1BitString:
            var data : [UInt8] = [UInt8(object.unusedBits)]
            if object.unusedBits == 0 {
                data += object.value
            }
            else {
                let mask : UInt8 = 0xff - (UInt8(1 << object.unusedBits) - 1)
                data += object.value[0 ..< (object.value.count - 1)]
                data += [object.value[object.value.count - 1] & mask]
            }
            
            return dataForObjectType(ASN1TypeTag.BITSTRING, content: data)
            
        case let object as ASN1OctetString:
            return dataForObjectType(ASN1TypeTag.OCTET_STRING, content: object.value)
            
        case _ as ASN1Null:
            return [ASN1TypeTag.NULL.rawValue, 0]


        case let object as ASN1ObjectIdentifier:
            var data = [UInt8]()
            let firstTwo = UInt8(object.identifier[0] * 40 + object.identifier[1])
            data += [firstTwo]
            for var v in object.identifier[2 ..< object.identifier.count]
            {
                var values = [Int]()
                repeat {
                    values.append(v & 0x7f)
                    v = v >> 7
                } while v != 0
                
                // values are reversed (little endian)
                data += values[1 ..< values.count].reversed().map {UInt8(0x80 | $0)}
                data += [UInt8(values[0])]
            }
            
            return dataForObjectType(ASN1TypeTag.OBJECT_IDENTIFIER, content: data)

        case let object as ASN1UTF8String:
            let data = [UInt8](object.string.utf8)
            return dataForObjectType(ASN1TypeTag.UTF8STRING, content: data)
            
        case let object as ASN1Sequence:
            var data  = [UInt8]()
            for o in object.objects {
                data += dataFromObject(o)
            }
            
            return dataForObjectType(ASN1TypeTag.SEQUENCE, content: data)

        case let object as ASN1Set:
            var data  = [UInt8]()
            for o in object.objects {
                data += dataFromObject(o)
            }
            
            return dataForObjectType(ASN1TypeTag.SET, content: data)
            
//        case let object as ASN1UTCTime:
            
        default:
            return []
        }
    }
}
