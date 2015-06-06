//
//  BigInt.swift
//  Chat
//
//  Created by Nico Schmidt on 19.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

struct BigInt {

    typealias PrimitiveType = UInt64
    var parts: [PrimitiveType]
    var sign : Bool
    
    init(_ a : Int) {
        if a == 0 {
            parts = []
            sign = false
            return
        }

        parts = [PrimitiveType(abs(a))]
        sign = a < 0
    }

    init<T where T : UnsignedIntegerType>(_ a : T) {
        if a == 0 {
            parts = []
            sign = false
            return
        }
        
        parts = [PrimitiveType(a.toUIntMax())]
        sign = false
    }

    init(capacity: Int) {
        parts = [PrimitiveType]()
        parts.reserveCapacity(capacity)
        sign = false
    }
    
    init<T where T : UnsignedIntegerType>(_ parts : [T], negative: Bool = false)
    {
        let numberInPrimitiveType = sizeof(PrimitiveType)/sizeof(T)
        
        if numberInPrimitiveType == 1 {
            self.parts = unsafeBitCast(parts, [PrimitiveType].self)
            self.sign = negative
            return
        }
        
        var number = [PrimitiveType](count: parts.count / numberInPrimitiveType + ((parts.count % sizeof(PrimitiveType) == 0) ? 0 : 1), repeatedValue: 0)
        var index = 0
        var numberIndex = 0
        var n : PrimitiveType = 0
        var a : T
        
        var numberOfFirstParts = parts.count % numberInPrimitiveType
        
        for a in parts
        {
            n = n << PrimitiveType(sizeof(T) * 8)
            n = n + a.toUIntMax()
            
            if numberOfFirstParts != 0 && (index + 1) == numberOfFirstParts
            {
                number[numberIndex] = n
                index = 0
                n = 0
                numberOfFirstParts = 0
                numberIndex += 1
            }
            else if index + 1 % numberInPrimitiveType == 0
            {
                number[numberIndex] = n
                index = 0
                n = 0
                numberIndex += 1
            }
            else {
                index += 1
            }
        }
        
        if n != 0 {
            number[numberIndex] = n
        }
        
        self.parts = number
        sign = negative
    }
    
}

func +(var a : BigInt, var b : BigInt) -> BigInt
{
    if a.sign != b.sign {
        if a.sign {
            return b - (-a)
        }
        else {
            return a - (-b)
        }
    }
    
    var count = max(a.parts.count, b.parts.count)
    var v = BigInt(capacity: count)
    v.sign = a.sign
    
    var carry : BigInt.PrimitiveType = 0
    for var i=0; i < count; ++i {
        var sum : BigInt.PrimitiveType = carry
        var overflow : Bool
        carry = 0
        
        if i < a.parts.count {
            (sum, overflow) = BigInt.PrimitiveType.addWithOverflow(sum, a.parts[i])

            if overflow {
                carry = 1
            }
        }

        if i < b.parts.count {
            (sum, overflow) = BigInt.PrimitiveType.addWithOverflow(sum, b.parts[i])

            if overflow {
                carry = 1
            }
        }
        
        v.parts.append(sum)
    }
    
    if carry != 0 {
        v.parts.append(carry)
    }
    
    return v
}

func -(var a : BigInt, var b : BigInt) -> BigInt
{
    if a.sign != b.sign {
        if a.sign {
            return -((-a) + b)
        }
        else {
            return (a + (-b))
        }
    }
    
    if a.sign {
        return -((-a) + (-b))
    }
    
    assert(!a.sign && !b.sign)
    
    if a < b {
        return -(b - a)
    }
    
    var count = max(a.parts.count, b.parts.count)
    var v = BigInt(capacity: count)

    var carry : BigInt.PrimitiveType = 0
    for var i=0; i < count; ++i {
        var difference : BigInt.PrimitiveType = carry
        var overflow : Bool
        carry = 0
        
        if i < a.parts.count {
            (difference, overflow) = BigInt.PrimitiveType.subtractWithOverflow(a.parts[i], difference)
            
            if overflow {
                carry = 1
            }
        }
        
        if i < b.parts.count {
            (difference, overflow) = BigInt.PrimitiveType.subtractWithOverflow(difference, b.parts[i])
            
            if overflow {
                carry = 1
            }
        }
        
        if difference != 0 {
            v.parts.append(difference)
        }
    }
    
    assert(carry == 0)
    
    for var i = v.parts.count - 1; i >= 0; --i {
        if v.parts[i] == 0 {
            v.parts.removeLast()
        }
    }
    
    return v
}

//func *(var a : BigInt, var b : BigInt) -> BigInt
//{
//    var carry  = BigInt(0);
//    var result = BigInt(0);
//    
//    let aCount = a.parts.count;
//    let bCount = b.parts.count;
//    for var i = 0; i < aCount; ++i {
//       
//        var carry       : UInt64 = 0
//        var overflow    : Bool
//        
//        for var j = 0; j < bCount; ++j {
//
//            var lo      : UInt64 = 0
//            var hi      : UInt64 = 0
//
//            if carry != 0 {
//                carry = 0
//                (result.parts[i + j], overflow) = BigInt.PrimitiveType.addWithOverflow(result.parts[i + j], carry)
//            }
//            
//            NSC_multiply64(UInt64(a.parts[i]), UInt64(b.parts[j]), &lo, &hi)
//            
//            if lo == 0 && hi == 0 {
//                continue
//            }
//            
//            (result.parts[i + j], overflow) = BigInt.PrimitiveType.addWithOverflow(result.parts[i + j], lo)
//
//            if overflow {
//                (hi, overflow) = BigInt.PrimitiveType.addWithOverflow(hi, 1)
//                if overflow {
//                    carry = 1
//                }
//                else {
//                    (result.parts[i + j + 1], overflow) = BigInt.PrimitiveType.addWithOverflow(result.parts[i + j + 1], hi)
//                    if overflow {
//                        carry = 1
//                    }
//                }
//            }
//        }
//    }
//    
//}

func ==(lhs : BigInt, rhs : BigInt) -> Bool
{
    return lhs.parts == rhs.parts
}

func <(lhs : BigInt, rhs : BigInt) -> Bool
{
    if lhs.parts.count != rhs.parts.count {
        return lhs.parts.count < rhs.parts.count
    }

    if lhs.parts.count > 0 {
        return lhs.parts.last! < rhs.parts.last!
    }

    assert(lhs.parts.count == 0 && rhs.parts.count == 0)
    
    return false
}

func >(lhs : BigInt, rhs : BigInt) -> Bool
{
    if lhs.parts.count != rhs.parts.count {
        return lhs.parts.count > rhs.parts.count
    }
    
    if lhs.parts.count > 0 {
        return lhs.parts.last! > rhs.parts.last!
    }
    
    assert(lhs.parts.count == 0 && rhs.parts.count == 0)
    
    return false
}

prefix func -(var v : BigInt) -> BigInt {
    v.sign = !v.sign
    return v
}