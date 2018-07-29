//
//  BigInt.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.09.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

public struct BigInt
{
    public typealias Word = UInt
    public typealias Words = [Word]
    public var words: Words {
        get {
            guard sign else {
                return _words
            }
            
            return self.twosComplement
        }
        set {
            guard !newValue.isEmpty else {
                _words = []
                sign = false
                
                return
            }

            _words = newValue
//            let shift = Word((MemoryLayout<Word>.size * 8) - 1)
//            let highestBitMask : Word = 1 << shift
//
//            if highestBitMask & newValue.last! != 0 {
//                let temp = BigInt(newValue)
//                _words = temp.twosComplement
//                sign = true
//            }
        }
    }
    
    fileprivate var _words: Words = []
    public var sign: Bool = false
    
    public static var isSigned: Bool {
        return true
    }
    
    var twosComplement: Words {
        get {
            let count = _words.count
            var v = [Word]()
            v.reserveCapacity(count)
            
            var carry : Word = 1
            for i in 0 ..< count {
                var sum : Word = carry
                var overflow : Bool
                carry = 0
                
                if i < _words.count {
                    (sum, overflow) = sum.addingReportingOverflow(~_words[i])
                    
                    if overflow {
                        carry = 1
                    }
                }
                
                v.append(sum)
            }
            
            return v

        }
    }
}

extension BigInt
{
    init?(hexString : String)
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
        
        self.init(bytes.reversed())
        self.normalize()
    }
    
    init(bigEndianParts: [UInt8]) {
        self.init(bigEndianParts.reversed())
    }
    
    init(_ a : Int) {
        self.init([UInt(abs(a))], negative: a < 0)
    }
    
    init(_ a : UInt, negative: Bool = false) {
        self.init([a], negative: negative)
    }

    init<T : UnsignedInteger>(_ a : T) {
        self.init([a])
    }
    
    init(count: Int)
    {
        self._words = [Word](repeating: 0, count: count)
    }

    /// parts are given in little endian order
    init<T : UnsignedInteger>(_ parts : [T], negative: Bool = false, normalized: Bool = true)
    {
        let numberInPrimitiveType = MemoryLayout<Word>.size/MemoryLayout<T>.size
        
        if numberInPrimitiveType == 1 {
            self._words = parts.map({Word($0)})
            self.sign = negative
            return
        }
        
        if numberInPrimitiveType > 0 {
            
            var number = [Word](repeating: 0, count: parts.count / numberInPrimitiveType + ((parts.count % MemoryLayout<Word>.size == 0) ? 0 : 1))
            var index = 0
            var numberIndex = 0
            var n : UInt = 0
            var shift = UInt(0)
            
            for a in parts
            {
                n = n + UInt(a) << shift
                shift = shift + UInt(MemoryLayout<T>.size * 8)
                
                if (index + 1) % numberInPrimitiveType == 0
                {
                    number[numberIndex] = Word(n)
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
                number[numberIndex] = Word(n)
            }
            
            if normalized {
                while number.last != nil && number.last! == 0 {
                    number.removeLast()
                }
            }

            self._words = number
        }
        else {
            // T is a larger type than Word
            let n = MemoryLayout<T>.size/MemoryLayout<Word>.size
            var number = [Word]()
            
            for a in parts
            {
                let shift : UInt = UInt(8 * MemoryLayout<Word>.size)
                var mask : UInt = (0xffffffffffffffff >> UInt(64 - shift))
                for i in 0 ..< n
                {
                    let part = Word((UInt(a) & mask) >> (UInt(i) * shift))
                    number.append(part)
                    mask = mask << shift
                }
            }
            
            if normalized {
                while number.last != nil && number.last! == 0 {
                    number.removeLast()
                }
            }
            
            self._words = number
        }
        
        self.sign = negative
    }

    init<T : UnsignedInteger>(_ parts : ArraySlice<T>, negative: Bool = false)
    {
        self.init([T](parts), negative: negative)
    }

    mutating func mask(upToHighestBit: Int)
    {
        var numWords = upToHighestBit >> Word.bitWidth.trailingZeroBitCount
        let numBits = upToHighestBit - numWords << Word.bitWidth.trailingZeroBitCount

        if numBits != 0 {
            numWords += 1
        }
        
        guard numWords <= self.words.count else { return }
        
        self.words.removeLast(self.words.count - numWords)
        if numBits != 0 {
            self.words[numWords - 1] &= (1 << numBits) - 1
        }
        
        self.normalize()
    }
    
    mutating func normalize()
    {
        while _words.last != nil && _words.last! == 0 {
            _words.removeLast()
        }
    }

    func asBigEndianData() -> [UInt8] {
        return BigInt.convert(self.words, normalized: false).reversed()
    }
    
    static func random(_ max : BigInt) -> BigInt
    {
        let num = max._words.count
        var n = BigInt(bigEndianParts: TLSRandomBytes(count: num * MemoryLayout<Word>.size))
                
        n.normalize()
        
        n = n % max
        
        return n
    }

    var isZero: Bool {
        get {
            return _words.count == 0 || (_words.count == 1 && _words[0] == 0)
        }
    }
}

extension BigInt : ExpressibleByIntegerLiteral
{
    public typealias IntegerLiteralType = Int

    public init(integerLiteral value: Int)
    {
        precondition(value >= 0)
        
        self.init(value)
    }
}

extension BigInt : Equatable
{
    public static func ==(lhs: BigInt, rhs: BigInt) -> Bool {
        return (lhs.words == rhs.words && lhs.sign == rhs.sign) ||
               (lhs.isZero && rhs.isZero)
    }
}

extension BigInt : Comparable
{
    public static func <(lhs: BigInt, rhs: BigInt) -> Bool {
        if lhs.sign != rhs.sign {
            return lhs.sign
        }
        
        if lhs.sign {
            return -lhs > -rhs
        }
        
        if lhs._words.count != rhs._words.count {
            return lhs._words.count < rhs._words.count
        }
        
        if lhs._words.count > 0 {
            for i in (0 ..< lhs._words.count).reversed()
            {
                if lhs._words[i] == rhs._words[i] {
                    continue
                }
                
                return lhs._words[i] < rhs._words[i]
            }
            
            return false
        }
        
        assert(lhs._words.count == 0 && rhs._words.count == 0)
        
        return false
    }
    
    public static func >(lhs: BigInt, rhs: BigInt) -> Bool {

        if lhs.sign != rhs.sign {
            return rhs.sign
        }
        
        if lhs.sign {
            return -lhs < -rhs
        }
        
        if lhs._words.count != rhs._words.count {
            if lhs.isZero && rhs.isZero {
                return false
            }
            
            return lhs._words.count > rhs._words.count
        }
        
        if lhs._words.count > 0 {
            for i in (0 ..< lhs._words.count).reversed()
            {
                if lhs._words[i] == rhs._words[i] {
                    continue
                }
                
                return lhs._words[i] > rhs._words[i]
            }
            
            return false
        }
        
        assert(lhs._words.count == 0 && rhs._words.count == 0)
        
        return false
    }
}

extension Array: Hashable where Element: Hashable {
    public var hashValue: Int {
        return self.reduce(0, { $0 ^ $1.hashValue})
    }
}

extension BigInt : Hashable
{
    public var hashValue: Int {
        return _words.hashValue
    }
}

extension BigInt : Numeric
{
    public init?<T>(exactly source: T) where T : BinaryInteger {
        fatalError()
    }
    
    public typealias Magnitude = BigInt
    
    public var magnitude: BigInt {
        return BigInt()
    }
    
    init(capacity: Int) {
        _words = [Word]()
        _words.reserveCapacity(capacity)
    }

    public static func +(a: BigInt, b: BigInt) -> BigInt {
        
        if a.sign != b.sign {
            if a.sign {
                return b - (-a)
            }
            else {
                return a - (-b)
            }
        }
        
        let count = max(a._words.count, b._words.count)
        var v = BigInt(capacity: count)
        v.sign = a.sign

        var carry : Word = 0
        for i in 0 ..< count {
            var sum : Word = carry
            var overflow : Bool
            carry = 0
            
            if i < a._words.count {
                (sum, overflow) = sum.addingReportingOverflow(a._words[i])
                
                if overflow {
                    carry = 1
                }
            }
            
            if i < b._words.count {
                (sum, overflow) = sum.addingReportingOverflow(b._words[i])
                
                if overflow {
                    carry = 1
                }
            }
            
            v._words.append(sum)
        }
        
        if carry != 0 {
            v._words.append(carry)
        }
        
        return v
    }
    
    public static func +=(lhs: inout BigInt, rhs: BigInt) {
        fatalError()
    }
    
    
    public static func -(a: BigInt, b: BigInt) -> BigInt {
        var a = a
        var b = b
        
        a.normalize()
        b.normalize()
        
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
        
        let count = max(a._words.count, b._words.count)
        var v = BigInt(count: count)
        
        var carry = BigInt.Word(0)
        for i in 0 ..< count {
            var difference : BigInt.Word = carry
            var overflow : Bool
            carry = 0
            
            if i < a._words.count {
                (difference, overflow) = a._words[i].subtractingReportingOverflow(difference)
                
                if overflow {
                    carry = 1
                }
            }
            
            if i < b._words.count {
                (difference, overflow) = difference.subtractingReportingOverflow(b._words[i])
                
                if overflow {
                    carry = 1
                }
            }
            
            v._words[i] = difference
        }
        
        assert(carry == 0)
        
        v.normalize()
        
        return v
    }
    
    public static func -=(lhs: inout BigInt, rhs: BigInt) {
        fatalError()
    }
    
    public static func *(a: BigInt, b: BigInt) -> BigInt {
        let aCount = a._words.count;
        let bCount = b._words.count;
        let resultCount = aCount + bCount
        
        var result = BigInt(count: resultCount)
        
        for i in 0 ..< aCount {
            
            var overflow    : Bool
            
            for j in 0 ..< bCount {
                
                let (_hi, _lo) = a._words[i].multipliedFullWidth(by: b._words[j])
                
                var hi = UInt64(_hi)
                var lo = UInt64(_lo)
                
                if lo == 0 && hi == 0 {
                    continue
                }
                
                if MemoryLayout<BigInt.Word>.size < MemoryLayout<UInt64>.size {
                    let shift : UInt64 = UInt64(8 * MemoryLayout<BigInt.Word>.size)
                    let mask : UInt64 = (0xffffffffffffffff >> UInt64(64 - shift))
                    hi = (lo & (mask << shift)) >> shift
                    lo = lo & mask
                }
                
                (result._words[i + j], overflow) = result._words[i + j].addingReportingOverflow(BigInt.Word(lo))
                
                if overflow {
                    hi += 1
                }
                
                var temp = hi
                var index = i + j + 1
                while true {
                    (result._words[index], overflow) = result._words[index].addingReportingOverflow(BigInt.Word(temp))
                    if overflow {
                        temp = 1
                        index += 1
                    }
                    else {
                        break
                    }
                }
            }
        }
        
        result.normalize()
        
        result.sign = (a.sign != b.sign)

        return result
    }
    
    public static func *=(lhs: inout BigInt, rhs: BigInt) {
        fatalError()
    }

}

public prefix func -(v : BigInt) -> BigInt {
    var v = v
    v.sign = !v.sign
    return v
}

extension BigInt : BinaryInteger
{
    /// Creates an integer from the given floating-point value, if it can be
    /// represented exactly.
    ///
    /// If the value passed as `source` is not representable exactly, the result
    /// is `nil`. In the following example, the constant `x` is successfully
    /// created from a value of `21.0`, while the attempt to initialize the
    /// constant `y` from `21.5` fails:
    ///
    ///     let x = Int(exactly: 21.0)
    ///     // x == Optional(21)
    ///     let y = Int(exactly: 21.5)
    ///     // y == nil
    ///
    /// - Parameter source: A floating-point value to convert to an integer.
    public init?<T>(exactly source: T) where T : BinaryFloatingPoint {
        
    }
    
    /// Creates an integer from the given floating-point value, rounding toward
    /// zero.
    ///
    /// Any fractional part of the value passed as `source` is removed, rounding
    /// the value toward zero.
    ///
    ///     let x = Int(21.5)
    ///     // x == 21
    ///     let y = Int(-21.5)
    ///     // y == -21
    ///
    /// If `source` is outside the bounds of this type after rounding toward
    /// zero, a runtime error may occur.
    ///
    ///     let z = UInt(-21.5)
    ///     // Error: ...the result would be less than UInt.min
    ///
    /// - Parameter source: A floating-point value to convert to an integer.
    ///   `source` must be representable in this type after rounding toward
    ///   zero.
    public init<T>(_ source: T) where T : BinaryFloatingPoint {
        
    }
    
    
    /// Creates a new instance from the given integer.
    ///
    /// If the value passed as `source` is not representable in this type, a
    /// runtime error may occur.
    ///
    ///     let x = -500 as Int
    ///     let y = Int32(x)
    ///     // y == -500
    ///
    ///     // -500 is not representable as a 'UInt32' instance
    ///     let z = UInt32(x)
    ///     // Error
    ///
    /// - Parameter source: An integer to convert. `source` must be representable
    ///   in this type.
    public init<T>(_ source: T) where T : BinaryInteger {
        self._words = source.words.map {UInt($0)}
    }
    
    /// Creates a new instance from the bit pattern of the given instance by
    /// sign-extending or truncating to fit this type.
    ///
    /// When the bit width of `T` (the type of `source`) is equal to or greater
    /// than this type's bit width, the result is the truncated
    /// least-significant bits of `source`. For example, when converting a
    /// 16-bit value to an 8-bit type, only the lower 8 bits of `source` are
    /// used.
    ///
    ///     let p: Int16 = -500
    ///     // 'p' has a binary representation of 11111110_00001100
    ///     let q = Int8(truncatingIfNeeded: p)
    ///     // q == 12
    ///     // 'q' has a binary representation of 00001100
    ///
    /// When the bit width of `T` is less than this type's bit width, the result
    /// is *sign-extended* to fill the remaining bits. That is, if `source` is
    /// negative, the result is padded with ones; otherwise, the result is
    /// padded with zeros.
    ///
    ///     let u: Int8 = 21
    ///     // 'u' has a binary representation of 00010101
    ///     let v = Int16(truncatingIfNeeded: u)
    ///     // v == 21
    ///     // 'v' has a binary representation of 00000000_00010101
    ///
    ///     let w: Int8 = -21
    ///     // 'w' has a binary representation of 11101011
    ///     let x = Int16(truncatingIfNeeded: w)
    ///     // x == -21
    ///     // 'x' has a binary representation of 11111111_11101011
    ///     let y = UInt16(truncatingIfNeeded: w)
    ///     // y == 65515
    ///     // 'y' has a binary representation of 11111111_11101011
    ///
    /// - Parameter source: An integer to convert to this type.
    public init<T>(truncatingIfNeeded source: T) where T : BinaryInteger {
        self.init(source)
    }
    
    /// Creates a new instance with the representable value that's closest to the
    /// given integer.
    ///
    /// If the value passed as `source` is greater than the maximum representable
    /// value in this type, the result is the type's `max` value. If `source` is
    /// less than the smallest representable value in this type, the result is
    /// the type's `min` value.
    ///
    /// In this example, `x` is initialized as an `Int8` instance by clamping
    /// `500` to the range `-128...127`, and `y` is initialized as a `UInt`
    /// instance by clamping `-500` to the range `0...UInt.max`.
    ///
    ///     let x = Int8(clamping: 500)
    ///     // x == 127
    ///     // x == Int8.max
    ///
    ///     let y = UInt(clamping: -500)
    ///     // y == 0
    ///
    /// - Parameter source: An integer to convert to this type.
    public init<T>(clamping source: T) where T : BinaryInteger {
        
    }

    static let maximumShift = 1 << 20
    public static func <<=<RHS>(lhs: inout BigInt, rhs: RHS) where RHS : BinaryInteger {
        guard rhs > 0 else {
            if rhs == 0 {
                return
            }

            lhs >>= rhs.magnitude
            return
        }

        if rhs > maximumShift {
            fatalError("BigInt doesn't support left shift larger than \(maximumShift)")
        }

        let shift = Int(rhs)

        let wordBitWidth = Word.bitWidth
        let wordShift = shift >> wordBitWidth.trailingZeroBitCount
        let bitShift = shift - (wordShift << wordBitWidth.trailingZeroBitCount)

        var words = Words(repeating: 0, count: wordShift)
        words.append(contentsOf: lhs.words)
        if bitShift == 0 {
            lhs.words = words
        }
        else {
            words.append(0)
            let count = words.count
            for i in (0..<count).reversed() {
                let lowerIndex = i - 1
                let upperIndex = i
                let lowerPart = lowerIndex >= 0 ? words[lowerIndex] >> (wordBitWidth - bitShift) : 0
                let upperPart = upperIndex >= 0 ? words[upperIndex] &<< bitShift : 0
                words[i] = upperPart ^ lowerPart
            }

            lhs.words = words
            lhs.normalize()
        }
    }
    
    public static func >>=<RHS>(lhs: inout BigInt, rhs: RHS) where RHS : BinaryInteger {
        guard rhs > 0 else {
            if rhs == 0 {
                return
            }
            lhs <<= rhs.magnitude
            return
        }
        
        if rhs > lhs.bitWidth {
            lhs = lhs.sign ? -1 : 0
            return
        }
        
        let shift = Int(rhs)

        let wordBitWidth = Word.bitWidth
        let wordShift = shift >> wordBitWidth.trailingZeroBitCount
        let bitShift = shift - (wordShift << wordBitWidth.trailingZeroBitCount)
        
        var words = lhs.words
        if bitShift == 0 {
            let count = words.count
            for i in 0..<count {
                let index = i + wordShift
                words[i] = index < count ? words[index] : 0
            }
        }
        else {
            let count = words.count
            for i in 0..<count {
                let lowerIndex = i + wordShift
                let upperIndex = i + wordShift + 1
                let lowerPart = lowerIndex < count ? words[lowerIndex] >> bitShift : 0
                let upperPart = upperIndex < count ? words[upperIndex] &<< (wordBitWidth - bitShift) : 0
                words[i] = upperPart ^ lowerPart
            }
        }

        lhs.words = words
        lhs.normalize()
    }
    
    public static prefix func ~(x: BigInt) -> BigInt {
        return BigInt(x._words.map {~$0})
    }
    
    public var bitWidth: Int {
        return _words.count * MemoryLayout<Word>.size * 8
    }
    
    public var trailingZeroBitCount: Int {
        return 0
    }
    
    // short division
    public static func /(u : BigInt, v : Int) -> BigInt
    {
        let sign = v < 0
        
        let unsignedV = Word(abs(v))
        
        var result = u / unsignedV
        result.sign = sign
        
        return result
    }
    
    public static func /(u : BigInt, v : UInt) -> BigInt
    {
        var r = Word(0)
        var q: Word
        let n = u._words.count
        let vv = Word(v)
        
        var result = BigInt(count: n)
        for i in (0 ..< n).reversed() {
            (q, r) = vv.dividingFullWidth((r, u._words[i]))
            
            result._words[i] = q
        }
        
        result.normalize()
        
        result.sign = u.sign
        
        return result
    }

    public static func /(u: BigInt, v: BigInt) -> BigInt {
        // This is an implementation of Algorithm D in
        // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
        if v.isZero {
            // handle error
            return BigInt(0)
        }
        
        let n = v._words.count
        let m = u._words.count - v._words.count
        
        if m < 0 {
            return BigInt(0)
        }
        
        if n == 1 && m == 0 {
            return BigInt(u._words[0] / v._words[0])
        }
        else if n == 1 {
            let divisor = UInt(v._words[0])
            
            var result = u / divisor
            
            if v.sign {
                result.sign = !result.sign
            }
            
            return result
        }
        
        return division(u, v).0
    }
    
    public static func /=(lhs: inout BigInt, rhs: BigInt) {
        
    }
    
    public static func %(lhs: BigInt, rhs: BigInt) -> BigInt {
        return division(lhs, rhs).1
    }
    
    public static func %=(lhs: inout BigInt, rhs: BigInt) {
        lhs = division(lhs, rhs).1
    }
    
    public static func &=(lhs: inout BigInt, rhs: BigInt) {
        fatalError()
    }
    
    public static func |=(lhs: inout BigInt, rhs: BigInt) {
        fatalError()
    }
    
    public static func ^=(lhs: inout BigInt, rhs: BigInt) {
        fatalError()
    }
    
    public func quotientAndRemainder(dividingBy rhs: BigInt) -> (quotient: BigInt, remainder: BigInt) {
        return (BigInt(), BigInt())
    }
    
    public var description: String {
        return "\(self)"
    }
    
    private static func short_division(_ u : BigInt, _ v : BigInt.Word) -> (BigInt, BigInt.Word)
    {
        var r = BigInt.Word(0)
        let n = u._words.count
        let vv = BigInt.Word(v)
        
        var q: BigInt.Word
        var result = BigInt(count: n)
        for i in (0 ..< n).reversed() {
            (q, r) = vv.dividingFullWidth((r, u._words[i]))
            
            result._words[i] = q
        }
        
        result.normalize()
        
        if u.sign != (v < 0) {
            result.sign = true
        }

        return (result, r)
    }

    private static func division(_ u : BigInt, _ v : BigInt) -> (BigInt, BigInt)
    {
        // This is an implementation of Algorithm D in
        // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
        if v.isZero {
            // handle error
            return (BigInt(0), BigInt(0))
        }
        
        if u.isZero {
            return (BigInt(0), BigInt(0))
        }
        
        let n = v._words.count
        let m = u._words.count - v._words.count
        
        if m < 0 {
            return (BigInt(0), u)
        }
        
        if n == 1 && m == 0 {
            let remainder = BigInt(u._words[0] % v._words[0], negative: u.sign)
            
            return (BigInt(u._words[0] / v._words[0]), remainder)
        }
        else if n == 1 {
            let divisor = v._words[0]
            
            let (quotient, remainder) = short_division(u, divisor)
            
            return (quotient, BigInt(remainder))
        }
     
        let uSign = u.sign

        var u = BigInt(u._words)
        var v = BigInt(v._words)
        
        var result = BigInt(count: m + 1)
        
        // normalize, so that v[0] >= base/2 (i.e. 2^31 in our case)
        let shift = BigInt.Word((MemoryLayout<Word>.size * 8) - 1)
        let highestBitMask : BigInt.Word = 1 << shift
        var hi = v._words[n - 1]
        var d = BigInt.Word(1)
        while (Word(hi) & Word(highestBitMask)) == 0
        {
            hi = hi << 1
            d  = d  << 1
        }
        
        if d != 1 {
            u = u * BigInt(d)
            v = v * BigInt(d)
        }
        
        if u._words.count < m + n + 1 {
            u._words.append(0)
        }
        
        for j in (0 ..< m+1).reversed()
        {
            // D3. Calculate q
            let (hi, lo) = (u._words[j + n], u._words[j + n - 1])
            let dividend: (BigInt.Word, BigInt.Word)
            
            let denominator = v._words[n - 1]
            // If the high word is greater or equal to the denominator we would overflow dividingFullWidth.
            // So in order to avoid that we are just dividing the high word, and rememember that the result
            // needs to be shifted. Since we made sure the highest bit is set in v before this can at most
            // result in a q of 1 (or so I convinced myself).
            let dividendIsShifted = hi >= denominator
            if !dividendIsShifted {
                dividend = (hi, lo)
            } else {
                dividend = (0, hi)
            }
            
            var (q, r) = denominator.dividingFullWidth(dividend)
            
            if q != 0 {
                var numIterationsThroughLoop = 0
                while true {
                    let qTimesV = q.multipliedFullWidth(by: v._words[n - 2])
                    guard qTimesV.0 > r ||
                          qTimesV.0 == r && qTimesV.1 > u._words[j + n - 2]
                    else {
                        break
                    }
                    
                    q = q - 1
                    if q == 0 && dividendIsShifted {
                        q = BigInt.Word.max
                    }
                    let overflow: Bool
                    (r, overflow) = r.addingReportingOverflow(denominator)
                    
                    if overflow {
                        break
                    }
                    
                    numIterationsThroughLoop += 1
                    
                    assert(numIterationsThroughLoop <= 2)
                }
                
                
                // D4. Multiply and subtract
                var vtemp = v
                vtemp._words.append(0)
                var temp = BigInt(u._words[j...j+n]) - vtemp * BigInt(q)

                // D6. handle negative case
                if temp.sign {
                    temp = temp + vtemp
                    q = q - 1
                }

                let count = temp._words.count
                for i in 0 ..< n {
                    u._words[j + i] = i < count ? temp._words[i] : 0
                }
            }
            
            result._words[j] = Word(q)
            
        }
        
        var q =  BigInt(result._words, negative: u.sign != v.sign)
        
        let uSlice = u._words[0..<n]
        var remainder = BigInt(uSlice, negative: uSign) / d

        q.normalize()
        remainder.normalize()
        
        return (q, remainder)
    }
    
    /// parts are given in little endian order
    static func convert<Source : UnsignedInteger, Target : UnsignedInteger>(_ words : [Source], normalized: Bool = true) -> [Target]
    {
        let numberInTarget = MemoryLayout<Target>.size/MemoryLayout<Source>.size
        
        if numberInTarget == 1 {
            return words.map({Target($0)})
        }
        
        if numberInTarget > 0 {
            
            var number = [Target](repeating: 0, count: words.count / numberInTarget + ((words.count % MemoryLayout<Target>.size == 0) ? 0 : 1))
            var index = 0
            var numberIndex = 0
            var n : UInt64 = 0
            var shift = UInt64(0)
            
            for a in words
            {
                n = n + UInt64(a) << shift
                shift = shift + UInt64(MemoryLayout<Source>.size * 8)
                
                if (index + 1) % numberInTarget == 0
                {
                    number[numberIndex] = Target(n)
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
                number[numberIndex] = Target(n)
            }
            
            return number
        }
        else {
            // T is a larger type than Target
            let n = MemoryLayout<Source>.size/MemoryLayout<Target>.size
            var number = [Target]()
            
            for a in words
            {
                let shift = UInt64(8 * MemoryLayout<Target>.size)
                var mask : UInt64 = (0xffffffffffffffff >> UInt64(64 - shift))
                for i in 0 ..< n
                {
                    let part : Target = Target((UInt64(a) & mask) >> (UInt64(i) * shift))
                    number.append(part)
                    mask = mask << shift
                }
            }
            
            if normalized {
                while number.last != nil && number.last! == 0 {
                    number.removeLast()
                }
            }
            
            return number
        }
    }

}

private extension String {
    init(stringInterpolationSegment expr : BigInt)
    {
        var s = ""
        var onlyZeroesYet = true
        let count = Int(expr._words.count)
        
        for i in (0..<count).reversed()
        {
            let part = expr._words[i]
            var c : UInt8
            
            var shift = (MemoryLayout<BigInt.Word>.size - 1) * 8
            var mask = UInt64(0xff) << UInt64(shift)
            for _ in 0 ..< MemoryLayout<BigInt.Word>.size
            {
                c = UInt8((UInt64(part) & mask) >> UInt64(shift))
                if !onlyZeroesYet || c != 0 {
                    s += hexString(c)
                    onlyZeroesYet = false
                }
                
                mask = mask >> 8
                shift = shift - 8
            }
        }
        
        if onlyZeroesYet {
            s = "0"
        }
        else if s.hasPrefix("0") {
            while s.hasPrefix("0") {
                s.removeFirst()
            }
        }
        
        self = expr.sign ? "-" + s : s
    }
}

