//
//  BigInt.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 17.09.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

public struct BigIntContext
{
    typealias Word = BigInt.Word
    typealias Buffer = UnsafeMutableBufferPointer<Word>

    var refCount: Int = 0

    // The buffer stack holds the nextBuffer and memory pointers at the last BigIntContext.open
    // When the context is closed, i.e. close() is called, they are used to reset the context to
    // the state when open() was called.
    private var bufferStack: [(Buffer, Buffer)] = []

    var memory: [Buffer] = []
    var nextBuffer: Buffer?
    static let memoryCapacity = 16384
    
    lazy var scratchSpace = Buffer.allocate(capacity: 1024)
    
    mutating func allocate(capacity: Int) -> Buffer {
        //        let n = buffers.count
        //        for i in 0..<n {
        //            let b = buffers[n - i - 1]
        //            if b.count >= capacity {
        //                buffers.remove(at: n - i - 1)
        //                return b
        //            }
        //        }

        if self.nextBuffer == nil || self.nextBuffer!.count < capacity {
            let memory = Buffer.allocate(capacity: BigIntContext.memoryCapacity)
//            memory.initialize(repeating: 0)
            self.memory.append(memory)
            self.nextBuffer = memory
        }

        if self.nextBuffer!.count >= capacity {
            let buffer = Buffer(start: self.nextBuffer!.baseAddress, count: capacity)
//            buffer.initialize(repeating: 0)
            
            self.nextBuffer = Buffer(start: self.nextBuffer!.baseAddress! + capacity, count: self.nextBuffer!.count - capacity)
            
            let memoryCount = UInt(bitPattern: self.nextBuffer!.baseAddress!) - UInt(bitPattern: self.memory.last!.baseAddress!)
            if maxMemory < memoryCount {
                maxMemory = memoryCount
            }
            
            return buffer
        }
        
        return Buffer.allocate(capacity: capacity + 1)
    }
    
    mutating func deallocate() {
        for chunk in memory {
            chunk.deallocate()
        }
        scratchSpace.deallocate()
    }
        
    @TaskLocal static var context: UnsafeMutablePointer<BigIntContext>?
    static func getContext() -> UnsafeMutablePointer<BigIntContext>? {
        if let context = Self.context {
            return context
        }

        return newContext()
    }

    static func newContext() -> UnsafeMutablePointer<BigIntContext> {
        guard let context = BigIntContext.context else {
            let contextPointer = UnsafeMutablePointer<BigIntContext>.allocate(capacity: 1)
            contextPointer.initialize(to: BigIntContext())
            return contextPointer
        }
        
        return context
    }
    
    var maxMemory: UInt = 0
    mutating func open() {
        self.refCount += 1
        // Force self.memory and self.nextBuffer to be initialized
        _ = allocate(capacity: 0)
        
        bufferStack.append((self.nextBuffer!, self.memory.last!))
    }

    mutating func close()  {
        self.refCount -= 1
        rewindBufferStack()
        
        if self.refCount == 0 {
//            print("max memory: \(maxMemory)")

//            _ = BigIntContext.setContext(nil)
        }
    }

    mutating func close(withResult result: BigInt) -> BigInt {
//        return result
        self.refCount -= 1
        let count = result.storage.count
        if scratchSpace.count < count {
            scratchSpace.deallocate()
            scratchSpace = Buffer.allocate(capacity: count * 2)
        }

        let storageBuffer = Buffer(start: scratchSpace.baseAddress, count: result.storage.count)
        _ = storageBuffer.initialize(from: result.storage)
        var storage = BigIntStorage(storage: .externallyManaged(storageBuffer))
        rewindBufferStack()
        
        if self.refCount == 0 {
            let result = BigInt.externalBigInt(from: result)
//            print("max memory: \(maxMemory)")

//            _ = BigIntContext.setContext(nil)

            return result
        }
        else {
//            print("max memory: \(maxMemory)")
            return BigInt(storage: storage.copy(), sign: result.sign)
        }
    }

    mutating func close(withResult result: (BigInt, BigInt)) -> (BigInt, BigInt) {
//        return result
        
        self.refCount -= 1
        let count = result.0.storage.count + result.1.storage.count
        if scratchSpace.count < count {
            scratchSpace.deallocate()
            scratchSpace = Buffer.allocate(capacity: count * 2)
        }

        let storage1Buffer = Buffer(start: scratchSpace.baseAddress, count: result.0.storage.count)
        _ = storage1Buffer.initialize(from: result.0.storage)
        var storage1 = BigIntStorage(storage: .externallyManaged(storage1Buffer))
        let storage2Buffer = Buffer(start: scratchSpace.baseAddress! + result.0.storage.count, count: result.1.storage.count)
        _ = storage2Buffer.initialize(from: result.1.storage)
        var storage2 = BigIntStorage(storage: .externallyManaged(storage2Buffer))
        rewindBufferStack()
        
        if self.refCount == 0 {
            let result = (BigInt.externalBigInt(from: result.0), BigInt.externalBigInt(from: result.1))
//            print("max memory: \(maxMemory)")

//            _ = BigIntContext.setContext(nil)

            return result
        }
        else {
//            print("max memory: \(maxMemory)")

            return (
                BigInt(storage: storage1.copy(), sign: result.0.sign),
                BigInt(storage: storage2.copy(), sign: result.1.sign)
            )
        }
    }
    
    mutating func rewindBufferStack() {
        let (nextBuffer, nextMemory) = bufferStack.last!
        self.nextBuffer = nextBuffer
        _ = bufferStack.popLast()
        for i in (0..<self.memory.count).reversed() {
            guard self.memory[i].baseAddress != nextMemory.baseAddress else {
                break
            }
            
            if let memory = self.memory.popLast() {
                memory.deallocate()
            }
        }
    }
}

extension BigInt {
    static func externalBigInt(from bigInt: BigInt) -> BigInt {
        switch bigInt.storage.storage {
        case .externallyManaged(let buffer):
            var array = [Word]()
            array.append(contentsOf: buffer[0..<bigInt.storage.count])
            var bigIntStorage = BigIntStorage(externalWithCapacity: bigInt.storage.count)
            bigIntStorage.storage = BigIntStorage.Storage.internallyManaged(array)
            bigIntStorage.count = bigInt.storage.count
            return BigInt(storage: bigIntStorage, sign: bigInt.sign)
            
        case .internallyManaged(_): return bigInt
        }
    }

    public static func withContext<Result>(_ context: UnsafeMutablePointer<BigIntContext>? = nil, _ block: (_ context: UnsafeMutablePointer<BigIntContext>) -> Result) -> Result {
        let context = context ?? BigIntContext.newContext()
        
        return BigIntContext.$context.withValue(context) {
            context.pointee.open()
            let result = block(context)
            context.pointee.close()
            return result
        }
    }

    public static func withContext<Result>(_ context: UnsafeMutablePointer<BigIntContext>? = nil, _ block: (_ context: UnsafeMutablePointer<BigIntContext>) throws -> Result) throws -> Result {
        let context = context ?? BigIntContext.newContext()
        
        context.pointee.open()
        let result = try block(context)
        context.pointee.close()
        
        return result
    }

    public static func withContext<Result>(_ context: UnsafeMutablePointer<BigIntContext>? = nil, _ block: (_ context: UnsafeMutablePointer<BigIntContext>) async throws -> Result) async throws -> Result {
        let context = context ?? BigIntContext.newContext()
        
        return try await BigIntContext.$context.withValue(context) {
            context.pointee.open()
            let result = try await block(context)
            context.pointee.close()
            
            return result
        }
    }

    public static func withContextReturningBigInt(_ context: UnsafeMutablePointer<BigIntContext>? = nil, _ block: (_ context: UnsafeMutablePointer<BigIntContext>) -> BigInt) -> BigInt {
        let context = context ?? BigIntContext.newContext()
        
        return BigIntContext.$context.withValue(context) {
            context.pointee.open()
            let result = block(context)
            return context.pointee.close(withResult: result)
        }
    }

    public static func withContextReturningBigInt(_ context: UnsafeMutablePointer<BigIntContext>? = nil, _ block: (_ context: UnsafeMutablePointer<BigIntContext>) throws -> BigInt) throws -> BigInt {
        let context = context ?? BigIntContext.newContext()
        
        return try BigIntContext.$context.withValue(context) {
            context.pointee.open()
            let result = try block(context)
            return context.pointee.close(withResult: result)
        }
    }

    public static func withContextReturningBigInt(_ context: UnsafeMutablePointer<BigIntContext>? = nil, _ block: (_ context: UnsafeMutablePointer<BigIntContext>) -> (BigInt, BigInt)) -> (BigInt, BigInt) {
        let context = context ?? BigIntContext.newContext()
        
        return BigIntContext.$context.withValue(context) {
            context.pointee.open()
            let result = block(context)
            return context.pointee.close(withResult: result)
        }
    }

}

public struct BigIntStorage {
    public typealias Word = BigInt.Word
    typealias Buffer = UnsafeMutableBufferPointer<Word>
    
    public var count: Int = 0
    
    public var first: Word? {
        guard self.count > 0 else {
            return nil
        }
        
        return self[0]
    }
    
    public var last: Word? {
        guard self.count > 0 else {
            return nil
        }
        
        return self[count - 1]
    }
    
    enum Storage : Sequence {
        case internallyManaged([Word])
        case externallyManaged(Buffer)
        
        subscript (_ i: Int) -> Word {
            get {
                switch self {
                case .externallyManaged(let buffer): return buffer[i]
                case .internallyManaged(let array): return array[i]
                }
            }
            set {
                switch self {
                case .externallyManaged(let buffer): buffer[i] = newValue
                case .internallyManaged(var array):
                    array[i] = newValue
                    self = .internallyManaged(array)
                }
            }
        }
        
        var count: Int {
            switch self {
            case .externallyManaged(let buffer): return buffer.count
            case .internallyManaged(let array): return array.count
            }
        }
        
        typealias Element = BigIntStorage.Word
        
        struct Iterator : IteratorProtocol {
            private var index = 0
            private var storage: Storage
            init(_ storage: Storage) {
                self.storage = storage
            }
            
            mutating func next() -> Element? {
                guard index < storage.count else {
                    return nil
                }
                
                let v = storage[index]
                index += 1
                
                return v
            }
        }
        
        func makeIterator() -> Storage.Iterator {
            return Iterator(self)
        }
    }
    
    var storage: Storage
    
    fileprivate init(storage: Storage)
    {
        self.storage = storage
        self.count = self.storage.count
    }
    
    fileprivate init(capacity: Int, context: UnsafeMutablePointer<BigIntContext>? = nil)
    {
        if let context = context ?? BigIntContext.getContext() {
            storage = .externallyManaged(context.pointee.allocate(capacity: capacity))
        }
        else {
            storage = .internallyManaged([Word](repeating: 0, count: capacity))
        }
        count = capacity
    }
    
    init(externalWithCapacity capacity: Int)
    {
        storage = .internallyManaged([Word](repeating: 0, count: capacity))
        count = capacity
    }
    
    func deallocate() {
    }
    
    mutating func initialize(repeating: Word, count: Int? = nil) {
        let count = count ?? storage.count
        switch storage {
        case .externallyManaged(let buffer):
            for i in 0..<count {
                buffer[i] = repeating
            }
        case .internallyManaged(var array):
            for i in 0..<count {
                array[i] = repeating
            }
            storage = .internallyManaged(array)
        }
    }

    mutating func initialize<S>(from source: S, count: Int? = nil) where S : Sequence, S.Element == Word {
        let count = count ?? storage.count
        switch storage {
        case .externallyManaged(let buffer):
            var sourceIterator = source.makeIterator()
            for i in 0..<count {
                if let v = sourceIterator.next() {
                    buffer[i] = v
                }
            }
        case .internallyManaged(var array):
            var sourceIterator = source.makeIterator()
            for i in 0..<count {
                if let v = sourceIterator.next() {
                    array[i] = v
                }
            }
            storage = .internallyManaged(array)
        }
    }

    func padded(count: Int, context: UnsafeMutablePointer<BigIntContext>? = nil) -> BigIntStorage {
        return BigIntStorage(storage: storage, count: self.count + count, normalized: false, context: context)
    }
    
    mutating func copy(padding: Int = 0, context: UnsafeMutablePointer<BigIntContext>? = nil) -> BigIntStorage {
        var storage = BigIntStorage(capacity: count + padding, context: context)
        storage.initialize(from: self)
        for i in 0..<padding {
            storage[count + i] = 0
        }
        storage.count = count + padding
        
        return storage
    }
    
    fileprivate init(storage: Storage, count: Int? = nil, normalized: Bool = true, context: UnsafeMutablePointer<BigIntContext>? = nil) {
        let count = count ?? storage.count
        
        if let context = context ?? BigIntContext.getContext() {
            self.storage = .externallyManaged(context.pointee.allocate(capacity: count))
        } else {
            self.storage = .internallyManaged([Word](repeating: 0, count: count))
        }
        
        switch (self.storage, storage) {
        case (.externallyManaged(let destination), .externallyManaged(let source)):
            memcpy(destination.baseAddress!, source.baseAddress!, source.count * MemoryLayout<Word>.size)
            
        default:
            self.initialize(from: storage)
        }
        
        self.count = count

        guard normalized else {
            for i in 0..<(count - storage.count) {
                self.storage[storage.count + i] = 0
            }
            return
        }

        normalize()
    }
    
    mutating func normalize() {
        var countOfNonZeroWords = count
        for i in 0..<count {
            if self.storage[count - i - 1] != 0 {
                break
            }
            
            countOfNonZeroWords -= 1
        }
        
        self.count = countOfNonZeroWords
    }
    
//    fileprivate static func allocateStorage(capacity: Int) -> Buffer {
//        return BigIntStorage.allocate(capacity: capacity)
//    }
    
    public subscript (_ i: Int) -> Word {
        get {
            return self.storage[i]
        }
        set {
            storage[i] = newValue
        }
    }
    
    // Return a BigIntStorage for the range given. The resulting object does not take ownership of the memory.
    // It is only safe as long as the original BigIntStorage is still around retaining the memory.
    fileprivate subscript (_ range: ClosedRange<Int>) -> BigIntStorage {
        get {
            switch storage {
            case .externallyManaged(let buffer):
                return BigIntStorage(storage: .externallyManaged(UnsafeMutableBufferPointer<Word>(rebasing: buffer[range])))
                
            case .internallyManaged(let array):
                return BigIntStorage(storage: .internallyManaged([Word](array[range])))
            }
        }
    }

    // Return a BigIntStorage for the range given. The resulting object does not take ownership of the memory.
    // It is only safe as long as the original BigIntStorage is still around retaining the memory.
    public subscript (_ range: Range<Int>) -> BigIntStorage {
        get {
            switch storage {
            case .externallyManaged(let buffer):
                return BigIntStorage(storage: .externallyManaged(UnsafeMutableBufferPointer<Word>(rebasing: buffer[range])))
                
            case .internallyManaged(let array):
                return BigIntStorage(storage: .internallyManaged([Word](array[range])))
            }
        }
        set {
           fatalError()
        }
    }
    
    fileprivate func map(_ transform : (Word) -> Word) -> BigIntStorage {
        var storage = BigIntStorage(capacity: count)
        for i in 0..<count {
            storage[i] = transform(self[i])
        }
        
        return storage
    }
    
}

extension BigIntStorage : Hashable {
    public static func ==(_ lhs: BigIntStorage, _ rhs: BigIntStorage) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        
        switch (lhs.storage, rhs.storage) {
        case (.externallyManaged(let a), .externallyManaged(let b)):
            return memcmp(UnsafeRawPointer(a.baseAddress!), UnsafeRawPointer(b.baseAddress!), lhs.count * MemoryLayout<Word>.size) == 0
        
        case (.internallyManaged(let a), .internallyManaged(let b)):
            return a[0..<lhs.count] == b[0..<rhs.count]
        
        case (.externallyManaged(let a), .internallyManaged(var b)):
            return memcmp(UnsafeRawPointer(a.baseAddress!), &b, lhs.count * MemoryLayout<Word>.size) == 0
        
        case (.internallyManaged(var a), .externallyManaged(let b)):
            return memcmp(&a, UnsafeRawPointer(b.baseAddress!), lhs.count * MemoryLayout<Word>.size) == 0
        }
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(storage[0])
    }
}

extension BigIntStorage : Sequence
{
    public typealias Element = BigIntStorage.Word
    
    public struct Iterator : IteratorProtocol {
        private var index = 0
        private var storage: BigIntStorage
        init(_ storage: BigIntStorage) {
            self.storage = storage
        }
        
        public mutating func next() -> Element? {
            guard index < storage.count else {
                return nil
            }
            
            let v = storage[index]
            index += 1
            
            return v
        }
    }
    
    public func makeIterator() -> BigIntStorage.Iterator {
        return Iterator(self)
    }
}

extension BigIntStorage : MutableCollection {
    public func index(after i: Int) -> Int {
        return i + 1
    }

    public var startIndex: Int {
        return 0
    }

    public var endIndex: Int {
        return count
    }
}

extension BigIntStorage : RandomAccessCollection {
}

public struct BigInt
{
    public typealias Word = UInt
    fileprivate var storage: BigIntStorage
    let sign: Bool
    
    init(storage: BigIntStorage, sign: Bool = false, normalized: Bool = true)
    {
        self.storage = storage
        self.sign = sign

        guard normalized else {
            return
        }

        self.storage.normalize()
    }
    
    init(_ v: Int)
    {
        guard v != 0 else {
            self.storage = BigIntStorage(capacity: 0)
            self.sign = false
            
            return
        }
        
        self.storage = BigIntStorage(capacity: 1)
        self.storage[0] = Word(v.magnitude)
        self.storage.count = 1
        self.sign = v < 0
    }
    
    init(_ v: UInt, sign: Bool = false)
    {
        guard v != 0 else {
            self.storage = BigIntStorage(capacity: 0)
            self.sign = false
            
            return
        }

        self.storage = BigIntStorage(capacity: 1)
        self.storage[0] = Word(v.magnitude)
        self.storage.count = 1
        self.sign = sign
    }
    
    init(bigEndianParts: [UInt8])
    {
        let littleEndian = bigEndianParts.reversed()
        self.init(littleEndian)
    }
    
    func asBigEndianData() -> [UInt8] {
        var result = [UInt8](repeating: 0, count: self.storage.count * MemoryLayout<Word>.size)
        try! BigInt.convert(from: self.storage, to: &result, count: self.storage.count)
        
        return result.reversed()
    }
    
    /// parts are given in little endian order
    init<Source: Collection>(_ number : Source, negative: Bool = false, normalized: Bool = true) where Source.Element : UnsignedInteger
    {
        let targetCount = (number.count * MemoryLayout<Source.Element>.size + MemoryLayout<Word>.size - 1) / MemoryLayout<Word>.size
        var target = BigIntStorage(capacity: targetCount)
//        try! BigInt.convert(from: number, to: &target)
        
        self.init(storage: target, sign: negative)
    }
    
    func padded(count: Int, context: UnsafeMutablePointer<BigIntContext>? = nil) -> BigInt {
        return BigInt(storage: self.storage.padded(count: count, context: context), normalized: false)
    }
    
    var isZero: Bool {
        get {
            return storage.count == 0 || (storage.count == 1 && storage[0] == 0)
        }
    }
    
    func isBitSet(_ bitNumber : Int) -> Bool {
        let wordSize    = MemoryLayout<Word>.size * 8
        let wordNumber  = bitNumber / wordSize
        let bit         = bitNumber % wordSize
        
        guard wordNumber < self.storage.count else {
            return false
        }
        
        return (UInt64(self.storage[wordNumber]) & (UInt64(1) << UInt64(bit))) != 0
    }
    
    func masked(upToHighestBit highestBit: Int) -> BigInt
    {
        var numWords = highestBit >> Word.bitWidth.trailingZeroBitCount
        let numBits = highestBit - numWords << Word.bitWidth.trailingZeroBitCount
        
        if numBits != 0 {
            numWords += 1
        }
        
        guard numWords <= self.storage.count else { return self }
        
        var result = BigIntStorage(capacity: numWords)
        result.initialize(from: self.storage, count: numWords)
        if numBits != 0 {
            result[numWords - 1] &= (1 << numBits) - 1
        }

        result.normalize()
        
        return BigInt(storage: result)
    }
    

    static func random(_ max : BigInt) -> BigInt
    {
        let num = max.storage.count
        var storage = BigIntStorage(capacity: num)
        switch storage.storage {
        case .externallyManaged(let buffer):
                TLSFillWithRandomBytes(UnsafeMutableRawBufferPointer(buffer))
        case .internallyManaged(var array):
            array.withUnsafeMutableBufferPointer { (buffer) in
                TLSFillWithRandomBytes(UnsafeMutableRawBufferPointer(buffer))
            }
            storage.storage = .internallyManaged(array)
        }
        
        var n = BigInt(storage: storage)

        n = n % max

        return n
    }

    enum ConversionError : Error {
        case sizeMismatch
    }
    /// parts are given in little endian order
    static func convert<Source: Collection, Target: MutableCollection>(from source: Source, to target: inout Target, count: Int? = nil) throws where Source.Element : UnsignedInteger, Target.Element : UnsignedInteger
    {
        let sourceCount = count ?? source.count
        let numberInTarget = MemoryLayout<Target.Element>.size/MemoryLayout<Source.Element>.size
        
        switch numberInTarget {
        case 1:
            guard sourceCount == target.count else {
                throw ConversionError.sizeMismatch
            }
            
            var sourceIterator = source.makeIterator()
            var index = target.startIndex

            while true {
                guard let v = sourceIterator.next() else { break }
                    
                target[index] = Target.Element(v)
                index = target.index(after: index)
            }
            
            return
        
        case 1...:
            let expectedTargetSize = sourceCount / numberInTarget + ((sourceCount % MemoryLayout<Target.Element>.size == 0) ? 0 : 1)
            guard target.count == expectedTargetSize else {
                throw ConversionError.sizeMismatch
            }

            var index = 0
            var n: Target.Element = 0
            var shift = UInt64(0)
            
            var sourceIterator = source.makeIterator()
            var targetIndex = target.startIndex
            
            for _ in 0..<sourceCount {
                guard let a = sourceIterator.next() else { break }
                
                n = n + Target.Element(a) << shift
                shift = shift + UInt64(MemoryLayout<Source.Element>.size * 8)
                
                if (index + 1) % numberInTarget == 0
                {
                    target[targetIndex] = n
                    index = 0
                    n = 0
                    shift = 0
                    targetIndex = target.index(after: targetIndex)
                }
                else {
                    index += 1
                }
            }
            
            if targetIndex < target.endIndex {
                target[targetIndex] = n
            }
            
            return

        default:
            // T is a larger type than Target
            let n = MemoryLayout<Source.Element>.size/MemoryLayout<Target.Element>.size
            guard target.count == n * sourceCount else {
                throw ConversionError.sizeMismatch
            }
            
            var sourceIterator = source.makeIterator()
            var targetIndex = target.startIndex
            
            for _ in 0..<sourceCount {
                guard let a = sourceIterator.next() else { break }

                let shift = UInt64(8 * MemoryLayout<Target.Element>.size)
                var mask : UInt64 = (0xffffffffffffffff >> UInt64(64 - shift))
                for i in 0 ..< n
                {
                    let part = Target.Element((UInt64(a) & mask) >> (UInt64(i) * shift))
                    target[targetIndex] = part
                    mask = mask << shift
                    
                    targetIndex = target.index(after: targetIndex)
                }
            }
        }
    }

    // short division
    public static func /(u : BigInt, v : Int) -> BigInt
    {
        let sign = v < 0
        
        let unsignedV = Word(abs(v))
        
        let result = u / unsignedV
        
        return sign ? -result : result
    }
    
    public static func /(u : BigInt, v : Word) -> BigInt
    {
        var r = Word(0)
        var q: Word
        let n = u.storage.count
        let vv = Word(v)
        
        var result = BigIntStorage(capacity: n)
        for i in (0 ..< n).reversed() {
            (q, r) = vv.dividingFullWidth((r, u.storage[i]))
            
            result[i] = q
        }
        
        return BigInt(storage: result, sign: u.sign)
    }

    private static func short_division(_ u : BigInt, _ v : BigInt.Word) -> (BigInt, BigInt.Word)
    {
        var r = BigInt.Word(0)
        let n = u.storage.count
        let vv = BigInt.Word(v)
        
        var q: BigInt.Word
        var result = BigIntStorage(capacity: n)
        for i in (0 ..< n).reversed() {
            (q, r) = vv.dividingFullWidth((r, u.storage[i]))
            
            result[i] = q
        }
        
        return (BigInt(storage: result, sign: u.sign != (v < 0)), r)
    }
    
    public static func /(u: BigInt, v: BigInt) -> BigInt {
        // This is an implementation of Algorithm D in
        // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
        if v.isZero {
            // handle error
            return BigInt(0)
        }
        
        let n = v.storage.count
        let m = u.storage.count - v.storage.count
        
        if m < 0 {
            return BigInt(0)
        }
        
        if n == 1 && m == 0 {
            return BigInt(u.storage[0] / v.storage[0])
        }
        else if n == 1 {
            let divisor = Word(v.storage[0])
            
            let result = u / divisor
            
            return v.sign ? -result : result
        }
        
        return divide(u, v).0
    }
    
    public static func /=(lhs: inout BigInt, rhs: BigInt) {
        lhs = lhs / rhs
    }
    
    public static func %(lhs: BigInt, rhs: BigInt) -> BigInt {
        return divide(lhs, rhs).1
    }
    
    public static func %=(lhs: inout BigInt, rhs: BigInt) {
        lhs = divide(lhs, rhs).1
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
        return BigInt.divide(self, rhs)
    }

    public static func divide(_ u : BigInt, _ v : BigInt, context: UnsafeMutablePointer<BigIntContext>? = nil) -> (BigInt, BigInt)
    {
        var u = u
        var v = v
        
        // This is an implementation of Algorithm D in
        // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
        if v.isZero {
            // handle error
            return (BigInt(0), BigInt(0))
        }
        
        if u.isZero {
            return (BigInt(0), BigInt(0))
        }
        
        let n = v.storage.count
        let m = u.storage.count - v.storage.count
        
        if m < 0 {
            return (BigInt(0), u)
        }
        
        if n == 1 && m == 0 {
            let remainder = BigInt(u.storage[0] % v.storage[0], sign: u.sign)
            
            return (BigInt(u.storage[0] / v.storage[0]), remainder)
        }
        else if n == 1 {
            let divisor = v.storage[0]
            
            let (quotient, remainder) = short_division(u, divisor)
            
            return (quotient, BigInt(remainder))
        }
        
        let uSign = u.sign
        
        var result = BigIntStorage(capacity: m + 1, context: context)
        
        // normalize, so that v[0] >= base/2 (i.e. 2^31 in our case)
        let shift = BigInt.Word((MemoryLayout<Word>.size * 8) - 1)
        let highestBitMask : BigInt.Word = 1 << shift
        var hi = v.storage[n - 1]
        var d = BigInt.Word(1)
        while (Word(hi) & Word(highestBitMask)) == 0
        {
            hi = hi << 1
            d  = d  << 1
        }
        
        if d != 1 {
            u = BigInt.multiply(u, BigInt(d), context: context)
            v = BigInt.multiply(v, BigInt(d), context: context)
        }
        
        if u.storage.count < m + n + 1 {
            u = u.padded(count: 1, context: context)
        }
        
        for j in (0 ..< m+1).reversed()
        {
            // D3. Calculate q
            let (hi, lo) = (u.storage[j + n], u.storage[j + n - 1])
            let dividend: (BigInt.Word, BigInt.Word)
            
            let denominator = v.storage[n - 1]
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
                    let qTimesV = q.multipliedFullWidth(by: v.storage[n - 2])
                    guard qTimesV.0 > r ||
                        qTimesV.0 == r && qTimesV.1 > u.storage[j + n - 2]
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
                var temp = BigInt(storage: u.storage[j...j+n]) - BigInt.multiply(v, BigInt(q), context: context)
                
                // D6. handle negative case
                if temp.sign {
                    temp = temp + v
                    q = q - 1
                }
                
                let count = temp.storage.count
                for i in 0 ..< n {
                    u.storage[j + i] = i < count ? temp.storage[i] : 0
                }
            }
            
            result[j] = Word(q)
        }
        
        let q = BigInt(storage: result, sign: u.sign != v.sign)
        let remainder = BigInt(storage: u.storage[0..<n], sign: uSign) / d
        
        return (q, remainder)
    }
}

extension BigInt : ExpressibleByIntegerLiteral {
    public typealias IntegerLiteralType = Int
    
    public init(integerLiteral value: Int)
    {
        self.init(value)
    }
}

extension BigInt : Hashable
{
    public func hash(into hasher: inout Hasher) {
        hasher.combine(storage)
    }
}

extension BigInt : Numeric {
    public typealias Magnitude = BigInt
    
    public static func +(_ lhs: BigInt, _ rhs: BigInt) -> BigInt {
        if lhs.sign != rhs.sign {
            if lhs.sign {
                return rhs - (-lhs)
            }
            else {
                return lhs - (-rhs)
            }
        }
        
        let count = max(lhs.storage.count, rhs.storage.count)
        // allocate storage for count + 1 words, because there might be an overflow
        var v = BigIntStorage(capacity: count + 1)
        
        var carry : Word = 0
        for i in 0 ..< count {
            var sum : Word = carry
            var overflow : Bool
            carry = 0
            
            if i < lhs.storage.count {
                (sum, overflow) = sum.addingReportingOverflow(lhs.storage[i])
                
                if overflow {
                    carry = 1
                }
            }
            
            if i < rhs.storage.count {
                (sum, overflow) = sum.addingReportingOverflow(rhs.storage[i])
                
                if overflow {
                    carry = 1
                }
            }
            
            v[i] = sum
        }
        
        v[count] = carry
        
        v.count = carry != 0 ? count + 1 : count
        
        return BigInt(storage: v, sign: lhs.sign)
    }
    
    public static func -(a: BigInt, b: BigInt) -> BigInt {
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
        
        let count = max(a.storage.count, b.storage.count)
        var v = BigIntStorage(capacity: count)
        
        var carry : Word = 0
        for i in 0 ..< count {
            var difference : Word = carry
            var overflow : Bool
            carry = 0
            
            if i < a.storage.count {
                (difference, overflow) = a.storage[i].subtractingReportingOverflow(difference)
                
                if overflow {
                    carry = 1
                }
            }
            
            if i < b.storage.count {
                (difference, overflow) = difference.subtractingReportingOverflow(b.storage[i])
                
                if overflow {
                    carry = 1
                }
            }
            
            v[i] = difference
        }
        
        assert(carry == 0)
        
        return BigInt(storage: v, sign: false)
    }
    
    public static prefix func -(_ v: BigInt) -> BigInt {
        return BigInt(storage: v.storage, sign: !v.sign)
    }
    
    public static func multiply(_ a: BigInt, _ b: BigInt, context: UnsafeMutablePointer<BigIntContext>? = nil) -> BigInt {
        let aCount = a.storage.count;
        let bCount = b.storage.count;
        let resultCount = aCount + bCount
        
        var result = BigIntStorage(capacity: resultCount, context: context)
        result.initialize(repeating: 0)
        
        for i in 0 ..< aCount {
            
            var overflow    : Bool
            
            for j in 0 ..< bCount {
                
                let (_hi, _lo) = a.storage[i].multipliedFullWidth(by: b.storage[j])
                
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
                
                (result[i + j], overflow) = result[i + j].addingReportingOverflow(BigInt.Word(lo))
                
                if overflow {
                    hi += 1
                }
                
                var temp = hi
                var index = i + j + 1
                while true {
                    (result[index], overflow) = result[index].addingReportingOverflow(BigInt.Word(temp))
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
        
        return BigInt(storage: result, sign: (a.sign != b.sign))
    }

    public static func *(a: BigInt, b: BigInt) -> BigInt {
        return multiply(a, b)
    }
    

    public static func -= (lhs: inout BigInt, rhs: BigInt) {
        lhs = lhs - rhs
    }
    
    public static func += (lhs: inout BigInt, rhs: BigInt) {
        lhs = lhs + rhs
    }
    
    public init?<T>(exactly source: T) where T : BinaryInteger {
        fatalError()
    }
    
    public var magnitude: BigInt {
        return BigInt(storage: storage, sign: false)
    }
    
    public static func *= (lhs: inout BigInt, rhs: BigInt) {
        lhs = lhs * rhs
    }
    
}

extension BigInt : BinaryInteger {
    public static var isSigned: Bool {
        return true
    }
    
    public var words: BigIntStorage {
        get {
            guard sign else {
                return storage
            }
            
            return self.twosComplement
        }
        set {
            fatalError()
        }

    }
    
    var twosComplement: BigIntStorage {
        get {
            var result = BigIntStorage(capacity: storage.count)
            let count = storage.count
            
            var carry : Word = 1
            for i in 0 ..< count {
                var sum : Word = carry
                var overflow : Bool
                carry = 0
                
                if i < storage.count {
                    (sum, overflow) = sum.addingReportingOverflow(~storage[i])
                    
                    if overflow {
                        carry = 1
                    }
                }
                
                result[i] = sum
            }
            
            return result
        }
    }
    
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
        fatalError()
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
        fatalError()
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
        var iterator = source.words.makeIterator()

        guard let v = iterator.next() else {
            fatalError()
        }
        
        // We are currently supporting only BinaryIntegers with one element
        guard iterator.next() == nil else {
            fatalError()
        }
        
        guard v != 0 else {
            self.storage = BigIntStorage(capacity: 0)
            self.sign = false
            
            return
        }
        
        self.storage = BigIntStorage(capacity: 1)
        self.storage[0] = Word(v.magnitude)
        self.sign = source.signum() == -1
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
        fatalError()
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
        
        let wordCount = wordShift + lhs.storage.count + (bitShift == 0 ? 0 : 1)
        var storage = BigIntStorage(capacity: wordCount)
        storage.initialize(repeating: 0, count: wordShift)
        for i in 0..<lhs.storage.count {
            storage[wordShift + i] = lhs.storage[i]
        }
        if bitShift == 0 {
            storage.normalize()
            lhs = BigInt(storage: storage)
        }
        else {
            storage[wordCount - 1] = 0
            let count = wordCount
            for i in (0..<count).reversed() {
                let lowerIndex = i - 1
                let upperIndex = i
                let lowerPart = lowerIndex >= 0 ? storage[lowerIndex] >> (wordBitWidth - bitShift) : 0
                let upperPart = upperIndex >= 0 ? storage[upperIndex] &<< bitShift : 0
                storage[i] = upperPart ^ lowerPart
            }
            
            storage.normalize()
            lhs = BigInt(storage: storage)
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
        
        let lhsWordCount = lhs.storage.count
        let wordCount = lhs.storage.count - wordShift
        var storage = BigIntStorage(capacity: wordCount)
        if bitShift == 0 {
            for i in 0..<wordCount {
                let index = i + wordShift
                storage[i] = lhs.storage[index]
            }
        }
        else {
            for i in 0..<wordCount {
                let lowerIndex = i + wordShift
                let upperIndex = i + wordShift + 1
                let lowerPart = lowerIndex < lhsWordCount ? lhs.storage[lowerIndex] >> bitShift : 0
                let upperPart = upperIndex < lhsWordCount ? lhs.storage[upperIndex] &<< (wordBitWidth - bitShift) : 0
                storage[i] = upperPart ^ lowerPart
            }
        }
        
        storage.normalize()
        lhs = BigInt(storage: storage)
    }

    public static prefix func ~(x: BigInt) -> BigInt {
        return BigInt(storage: x.storage.map {~$0})
    }
    
    public var bitWidth: Int {
        return storage.count * MemoryLayout<Word>.size * 8
    }
    
    public var trailingZeroBitCount: Int {
        fatalError()
    }
}

extension BigInt : Equatable {
    public static func == (lhs: BigInt, rhs: BigInt) -> Bool {
        guard lhs.storage.count == rhs.storage.count else {
            return false
        }
        
        return lhs.sign == rhs.sign && lhs.storage == rhs.storage
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
        
        if lhs.storage.count != rhs.storage.count {
            return lhs.storage.count < rhs.storage.count
        }
        
        if lhs.storage.count > 0 {
            for i in (0 ..< lhs.storage.count).reversed()
            {
                if lhs.storage[i] == rhs.storage[i] {
                    continue
                }
                
                return lhs.storage[i] < rhs.storage[i]
            }
            
            return false
        }
        
        assert(lhs.storage.count == 0 && rhs.storage.count == 0)
        
        return false
    }
    
    public static func >(lhs: BigInt, rhs: BigInt) -> Bool {
        
        if lhs.sign != rhs.sign {
            return rhs.sign
        }
        
        if lhs.sign {
            return -lhs < -rhs
        }
        
        if lhs.storage.count != rhs.storage.count {
            if lhs.isZero && rhs.isZero {
                return false
            }
            
            return lhs.storage.count > rhs.storage.count
        }
        
        if lhs.storage.count > 0 {
            for i in (0 ..< lhs.storage.count).reversed()
            {
                if lhs.storage[i] == rhs.storage[i] {
                    continue
                }
                
                return lhs.storage[i] > rhs.storage[i]
            }
            
            return false
        }
        
        assert(lhs.storage.count == 0 && rhs.storage.count == 0)
        
        return false
    }
}

extension BigInt {
    private init?<S>(hexString : S) where S : StringProtocol
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
        
        let padding = MemoryLayout<Word>.size - bytes.count % MemoryLayout<Word>.size
        bytes = [UInt8](repeating: 0, count: padding) + bytes
        bytes = bytes.reversed()
        var storage = BigIntStorage(capacity: bytes.count / MemoryLayout<Word>.size)
        bytes.withUnsafeMutableBytes { bytes in
            let ptr = UnsafeMutableRawBufferPointer(bytes)
            let uintbuffer = ptr.bindMemory(to: UInt.self)
            storage.initialize(from: uintbuffer)
            ptr.bindMemory(to: UInt8.self)
        }
        
        self.init(storage: storage, sign: false)
    }

    init?<S>(_ text: S, radix: Int = 10) where S : StringProtocol {
        var isNegative = false
        var isDroppingFirstCharacter = false
        switch text.first {
        case "-":
            isNegative = true
            fallthrough
        case "+":
            isDroppingFirstCharacter = true
        default:
            break
        }

        // make sure we have a subsequence by using dropFirst even if we don't need
        // to drop the first character. I have found no better way to generically construct
        // an S from an S.SubSequence
        let text = text.dropFirst(isDroppingFirstCharacter ? 1 : 0)

        var value: BigInt
        if radix == 16 {
            guard let v = BigInt(hexString: text) else {
                return nil
            }
            
            value = v
        }
        else {
            let bigIntRadix = BigInt(radix)
            value = BigInt.zero
            for digit in text {
                guard let d = Int(String(digit), radix: radix) else {
                    return nil
                }
                
                value = value * bigIntRadix + BigInt(d)
            }
        }

        self = isNegative ? -value : value
    }
    
    var hexString: String {
        return "\(self)"
    }
}

extension BigInt : CustomStringConvertible {
    public var description: String {
        return "\(self)"
    }
}

func hexDigit(_ d : UInt8) -> String
{
    switch (d & 0xf)
    {
    case 0:
        return "0"
    case 1:
        return "1"
    case 2:
        return "2"
    case 3:
        return "3"
    case 4:
        return "4"
    case 5:
        return "5"
    case 6:
        return "6"
    case 7:
        return "7"
    case 8:
        return "8"
    case 9:
        return "9"
    case 0xa:
        return "A"
    case 0xb:
        return "B"
    case 0xc:
        return "C"
    case 0xd:
        return "D"
    case 0xe:
        return "E"
    case 0xf:
        return "F"
        
    default:
        return "0"
    }
}

func hexString(_ c : UInt8) -> String
{
    return hexDigit((c & 0xf0) >> 4) + hexDigit(c & 0xf)
}

func hex(_ v: BigInt) -> String
{
    var s = ""
    switch v.storage.storage {
    case .externallyManaged(let buffer):
        let ptr = UnsafeMutableRawBufferPointer(buffer)
        let data = ptr.bindMemory(to: UInt8.self)
        
        let count = v.storage.count * MemoryLayout<BigIntStorage.Word>.size
        for i in 0 ..< count {
            let c = data[count - i - 1]
            //        if (i % 16 == 0 && i != 0) {
            //            s += "\n"
            //        }
            s += String(format: "%02x ", arguments: [c])
        }
        
        ptr.bindMemory(to: BigIntStorage.Word.self)
    case .internallyManaged(_):
        let data = [UInt8](v.asBigEndianData().reversed())
        let count = data.count
        for i in 0..<count {
            let c = data[count - i - 1]
            //        if (i % 16 == 0 && i != 0) {
            //            s += "\n"
            //        }
            s += String(format: "%02x ", arguments: [c])
        }
    }
    
    return v.sign ? "- " + s : s
}

extension String.StringInterpolation {
    mutating func appendInterpolation(_ value: BigInt) {
        var s = ""
        var onlyZeroesYet = true
        let count = Int(value.storage.count)
        
        for i in (0..<count).reversed()
        {
            let part = value.storage[i]
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
        
        appendLiteral(value.sign ? "-" + s : s)
    }
}
