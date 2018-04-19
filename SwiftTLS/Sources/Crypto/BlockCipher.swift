//
//  BlockCipher.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 12/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

extension UnsignedInteger where Self : FixedWidthInteger {
    init?<T : RandomAccessCollection>(bigEndianBytes: T) where T.Element == UInt8, T.Index == Int
    {
        guard bigEndianBytes.count <= Self.bitWidth / 8 else {
            return nil
        }
        
        self = bigEndianBytes.reduce(0 as Self, { $0 << 8 | Self($1)})
    }
    
    var bigEndianBytes: [UInt8] {
        
        let bitWidth = type(of: self).bitWidth
        
        var bytes = [UInt8]()
        var shift = bitWidth
        var mask  = Self(0xff) << (shift - 8)

        for _ in 0..<bitWidth / 8 {
            shift -= 8
            bytes.append(UInt8((self & mask) >> shift))
            mask = mask >> 8
        }
        
        return bytes
    }
    
//    var bytes: [UInt8] {
//        
//        let bitWidth = type(of: self).bitWidth
//        
//        let byteLength = bitWidth / 8
//        var bytes = [UInt8](repeating: 0, count: byteLength)
//        var shift = 0
//        var mask  = Self(0xff)
//        
//        for i in 0..<byteLength {
//            bytes[i] = UInt8(self & mask) >> shift
//            shift += 8
//            mask = mask << 8
//        }
//        
//        return bytes
//    }
//
}

class BlockCipher
{
    private var cryptor : Cryptor
    private var encrypt : Bool
    private var _IV : [UInt8]!
    private let mode: BlockCipherMode
    private let cipher : CipherAlgorithm
    var authTag : [UInt8]?

    var IV : [UInt8] {
        get {
            return _IV
        }
        set {
            _IV = newValue
        }
    }
    
    init?(encrypt: Bool, cryptor: Cryptor, mode: BlockCipherMode, cipher: CipherAlgorithm)
    {
        self.cryptor = cryptor
        self.encrypt = encrypt
        self.mode = mode
        
        switch cipher
        {
        case .aes128:
            self.cipher = .aes128
        
        case .aes256:
            self.cipher = .aes256
            
        default:
            return nil
        }
    }
    
    func update(data : [UInt8], key : [UInt8], IV : [UInt8]?) -> [UInt8]?
    {
        return update(data: data, authData: nil, key: key, IV: IV)
    }
    
    func update(data : [UInt8], authData: [UInt8]?, key : [UInt8], IV : [UInt8]?) -> [UInt8]?
    {
        switch self.mode
        {
        case .cbc:
            return updateCBC(data: data, key: key, IV: IV)

        case .gcm:
            return updateGCM(data: data, authData: authData, key: key, IV: IV)

        }
    }
    
    private func cryptorOutputLengthForInputLength(_ inputLength: Int) -> Int {
        return inputLength
//        return CCCryptorGetOutputLength(self.cryptor, inputLength, false)
    }
    
    func updateCBC(data inputData: [UInt8], key: [UInt8], IV: [UInt8]?) -> [UInt8]?
    {
        let outputLength = cryptorOutputLengthForInputLength(inputData.count)
        
        var outputData = [UInt8](repeating: 0, count: outputLength)
        
        if let IV = IV {
            self.IV = IV
        }
        
        let blockSize = self.cipher.blockSize
        let numSteps = outputLength / blockSize

        let isEncrypting = encrypt
        let isDecrypting = !encrypt
        
        var iv = MemoryBlock(self.IV)
        
        for i in 0..<numSteps {
            
            let range = (blockSize * i)..<(blockSize * (i + 1))
            
            var inputBlock  = MemoryBlock(inputData[range])
            var outputBlock = MemoryBlock(outputData[range])
            
            if isEncrypting {
                inputBlock ^= iv
            }

            if !cryptor.update(inputBlock: inputBlock, outputBlock: &outputBlock) {
                return nil
            }
            
            if isDecrypting {
                outputBlock ^= iv
                iv = inputBlock
            }
            else if isEncrypting {
                iv = outputBlock
            }

            outputData[range].replaceSubrange(range, with: outputBlock.block)
        }
        
        self.IV = iv.block
        
        return outputData
    }

    func updateGCM(data inputData: [UInt8], authData: [UInt8]?, key: [UInt8], IV initializationVector: [UInt8]?) -> [UInt8]?
    {
        let outputLength = cryptorOutputLengthForInputLength(inputData.count)
        
        var outputData = [UInt8](repeating: 0, count: outputLength)
        
        let blockSize = self.cipher.blockSize
        var numSteps = outputLength / blockSize
        if outputLength % blockSize != 0 {
            numSteps += 1
        }
        
        let isEncrypting = encrypt
        let isDecrypting = !encrypt
        
        var hBlock = MemoryBlock(blockSize: blockSize)
        _ = cryptor.update(inputBlock: hBlock, outputBlock: &hBlock)
        let H = GF2_128_Element(hBlock.block)!
        
        var IV : [UInt8]
        if let initializationVector = initializationVector {
            IV = initializationVector
        }
        else {
            IV = self.IV
        }

        if IV.count != 12 {
            let lenA = UInt64(0)
            let lenIV = UInt64(IV.count) << 3
            let len = lenA.bigEndianBytes + lenIV.bigEndianBytes
            let ivMAC = ghashUpdate(GF2_128_Element(), h: H, x: IV)
            IV = ghashUpdate(ivMAC, h: H, x: len).asBigEndianByteArray()
        }
        self.IV = IV

        var mac = GF2_128_Element(0)
        
        if let authData = authData, authData.count > 0 {
            mac = ghashUpdate(mac, h: H, x: authData)
        }
        
        if IV.count == 12 {
            IV.append(contentsOf: [0,0,0,1] as [UInt8])
        }
        
        var counter = MemoryBlock(IV, blockSize: blockSize)
        let c1 = UInt32(IV[12]) << UInt32(24)
        let c2 = UInt32(IV[13]) << UInt32(16)
        let c3 = UInt32(IV[14]) << UInt32(8)
        let c4 = UInt32(IV[15])
        
        var counter32 : UInt32 = c1 + c2 + c3 + c4
        
        let Y0 = counter
        
        let authDataCount = authData != nil ? authData!.count : 0
        
        for i in 0..<numSteps {

            counter32 += 1
            counter.block[12..<16] = counter32.bigEndianBytes[0..<4]

            let start = (blockSize * i)
            var end   = (blockSize * (i + 1))
            
            if end >= inputData.endIndex {
                end = inputData.endIndex
            }
            
            let range = start..<end
            
            var encrypted = MemoryBlock(blockSize: blockSize)
            if !cryptor.update(inputBlock: counter, outputBlock: &encrypted) {
                return nil
            }
            
            let inputBlock  = MemoryBlock(inputData[range], blockSize: end - start)
            encrypted = MemoryBlock(encrypted.block, blockSize: end - start)
            encrypted ^= inputBlock
            
            if isEncrypting {
                mac = ghashUpdate(mac, h: H, x: encrypted.block)
            }
            else if isDecrypting {
                mac = ghashUpdate(mac, h: H, x: inputBlock.block)
            }
            
            outputData[range].replaceSubrange(range, with: encrypted.block)
        }
        
        if inputData.count + authDataCount > 0 {
            let len = UInt64(authDataCount << 3).bigEndianBytes + UInt64(inputData.count << 3).bigEndianBytes
            mac = ghashUpdate(mac, h: H, x: len)
        }

        var authTag = MemoryBlock(blockSize: 16)
        _ = cryptor.update(inputBlock: Y0, outputBlock: &authTag)
        authTag ^= MemoryBlock(mac.hi.bigEndianBytes + mac.lo.bigEndianBytes)
        self.authTag = authTag.block
        
        return outputData
    }
}

struct MemoryBlock
{
    var block : [UInt8]

    init(_ array : [UInt8], blockSize : Int = 16)
    {
        var array = array
        if array.count < blockSize {
            array.append(contentsOf: [UInt8](repeating: 0, count: blockSize - array.count))
        }
        else if blockSize < array.count {
            array.removeLast(array.count - blockSize)
        }
        
        self.block = array
    }
    
    init(_ slice: ArraySlice<UInt8>, blockSize: Int = 16)
    {
        self = MemoryBlock([UInt8](slice), blockSize: blockSize)
    }
    
    init(blockSize: Int = 16)
    {
        self = MemoryBlock([UInt8](repeating: 0, count: blockSize), blockSize: blockSize)
    }
}

func ^= (lhs : inout MemoryBlock, other : MemoryBlock)
{
    precondition(lhs.block.count == other.block.count)
    
    for i in 0..<lhs.block.count {
        lhs.block[lhs.block.startIndex + i] ^= other.block[other.block.startIndex + i]
    }
}
