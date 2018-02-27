//
//  SMP+Extensions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05.11.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

typealias BigInt = BInt

extension BInt {
    typealias PrimitiveType = UInt64
    
    mutating func normalize()
    {
        while limbs.last != nil && limbs.last! == 0 {
            limbs.removeLast()
        }
    }

    public init<Word : FixedWidthInteger>(_ parts : [Word])
    {
        self.limbs = convert(parts)
        normalize()
    }

    public init<Word : FixedWidthInteger>(bigEndianParts : [Word])
    {
        self.init(bigEndianParts.reversed())
    }
    
    fileprivate func convert<T : FixedWidthInteger, U : FixedWidthInteger>(_ parts : [T]) -> [U]
    {
        let numberInPrimitiveType = MemoryLayout<U>.size/MemoryLayout<T>.size
        
        if numberInPrimitiveType == 1 {
            return parts.map({U($0)})
        }
        
        if numberInPrimitiveType > 0 {
            
            var number = [U](repeating: 0, count: parts.count / numberInPrimitiveType + ((parts.count % MemoryLayout<U>.size == 0) ? 0 : 1))
            var index = 0
            var numberIndex = 0
            var n : UInt64 = 0
            var shift = UInt64(0)
            
            for a in parts
            {
                n = n + UInt64(a) << shift
                shift = shift + UInt64(MemoryLayout<T>.size * 8)
                
                if (index + 1) % numberInPrimitiveType == 0
                {
                    number[numberIndex] = U(n)
                    index = 0
                    n = 0
                    shift = 0
                    numberIndex += 1
                }
                else {
                    index += 1
                }
            }
            
            if n != 0 {
                number[numberIndex] = U(n)
            }

            return number
        }
        else {
            // T is a larger type than PrimitiveType
            let n = MemoryLayout<T>.size/MemoryLayout<U>.size
            var number = [U]()
            
            for a in parts
            {
                let shift = UInt64(8 * MemoryLayout<U>.size)
                var mask : UInt64 = (0xffffffffffffffff >> UInt64(64 - shift))
                for i in 0 ..< n
                {
                    let part : U = U((UInt64(a) & mask) >> (UInt64(i) * shift))
                    number.append(part)
                    mask = mask << shift
                }
            }
            
            return  number
        }
    }

    init?(hexString : String, negative : Bool = false)
    {
        var bytes = [UInt8]()
        var bytesLeft = hexString.utf8.count
        var byte : UInt8 = 0
        for c in hexString.utf8
        {
            var a : UInt8
            switch (c)
            {
            case 0x30...0x39: // '0'...'9'
                a = c - 0x30
                
            case 0x41...0x46: // 'A'...'F'
                a = c - 0x41 + 0x0a
                
            case 0x61...0x66: // 'a'...'f'
                a = c - 0x61 + 0x0a
                
            default:
                return nil
            }
            
            byte = byte << 4 + a
            
            if bytesLeft & 0x1 == 1 {
                bytes.append(byte)
            }
            
            bytesLeft -= 1
        }
        
        self.init(bigEndianParts: bytes)
        self.sign = negative
    }
    
    func asBigEndianData() -> [UInt8] {
        return convert(self.limbs.reversed())
    }
    
    static func random(_ max : BigInt) -> BigInt
    {
        let num = max.limbs.count
        var words = [Limb](repeating: 0, count: num)
        
        words.withUnsafeMutableBufferPointer { arc4random_buf($0.baseAddress, num * MemoryLayout<Limb>.size); return }
        
        var n = BigInt(words)
        
        n = n % max
        
        return n
    }
}

extension BinaryInteger {
    func isBitSet(_ bitNumber : Int) -> Bool
    {
        let wordSize    = MemoryLayout<Words.Element>.size * 8
        let wordNumber  = bitNumber / wordSize
        let bit         = bitNumber % wordSize
        
        guard let words = self.words as? Array<Words.Element> else {
            fatalError("isBitSet is not implemented for anything but arrays")
        }
        
        guard wordNumber < words.count else {
            return false
        }
        
        return (UInt64(words[wordNumber]) & (UInt64(1) << UInt64(bit))) != 0
    }
}

