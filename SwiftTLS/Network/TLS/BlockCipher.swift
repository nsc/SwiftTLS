//
//  BlockCipher.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 12/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import CommonCrypto

class BlockCipher
{
    private var cryptor : CCCryptorRef
    private var encrypt : Bool
    private var _IV : [UInt8]!
    private let mode: BlockCipherMode
    private let cipher : CipherAlgorithm
    
    var IV : [UInt8] {
        get {
            return _IV
        }
        set {
            _IV = newValue
            CCCryptorReset(self.cryptor, &_IV)
        }
    }
    
    private init?(encrypt: Bool, cryptor: CCCryptorRef, mode: BlockCipherMode, cipher: CipherAlgorithm)
    {
        self.cryptor = cryptor
        self.encrypt = encrypt
        self.mode = mode
        
        switch cipher
        {
        case .AES128:
            self.cipher = .AES128
        
        case .AES256:
            self.cipher = .AES256
            
        default:
            return nil
        }
    }
    
    private class func CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm : CipherAlgorithm) -> CCAlgorithm?
    {
        switch (cipherAlgorithm)
        {
        case .AES128, .AES256:
            return CCAlgorithm(kCCAlgorithmAES)
            
        case .NULL:
            return nil
        }
    }
    
    class func encryptionBlockCipher(cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8], IV : [UInt8]) -> BlockCipher?
    {
        guard let algorithm = CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm) else { return nil }
        
        var encryptor : CCCryptorRef = nil
        
        var key = key
        var IV = IV
        
        let status = Int(CCCryptorCreate(CCOperation(kCCEncrypt), algorithm, UInt32(kCCOptionECBMode), &key, key.count, &IV, &encryptor))
        if status != kCCSuccess {
            return nil
        }

        let cipher = BlockCipher(encrypt: true, cryptor: encryptor, mode: mode, cipher: cipherAlgorithm)
        cipher!._IV = IV
        
        return cipher
    }
    
    class func decryptionBlockCipher(cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8], IV : [UInt8]) -> BlockCipher?
    {
        guard let algorithm = CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm) else { return nil }
        
        var decryptor : CCCryptorRef = nil
        
        var key = key
        var IV = IV
        let status = Int(CCCryptorCreate(CCOperation(kCCDecrypt), algorithm, UInt32(kCCOptionECBMode), &key, key.count, &IV, &decryptor))
        if status != kCCSuccess {
            return nil
        }
        
        let cipher = BlockCipher(encrypt: false, cryptor: decryptor, mode: mode, cipher: cipherAlgorithm)
        cipher!._IV = IV
        
        return cipher
    }

    func update(data data : [UInt8], key : [UInt8], IV : [UInt8]?) -> [UInt8]?
    {
        switch self.mode
        {
        case .CBC:
            return updateCBC(data: data, key: key, IV: IV)
        
        default:
            return nil
        }
    }
    
    func updateCBC(data inputData : [UInt8], key : [UInt8], IV : [UInt8]?) -> [UInt8]?
    {
        let outputLength : Int = CCCryptorGetOutputLength(self.cryptor, inputData.count, false)
        
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
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

            var outputDataWritten : Int = 0
            let status = Int(CCCryptorUpdate(self.cryptor, &inputBlock.block, blockSize, &outputBlock.block, blockSize, &outputDataWritten))
            if status != kCCSuccess {
                return nil
            }
            
            assert(outputDataWritten == blockSize)
            
            if isDecrypting {
                outputBlock ^= iv
                iv = inputBlock
            }
            else if isEncrypting {
                iv = outputBlock
            }

            outputData[range].replaceRange(range, with: outputBlock.block)
        }
        
        return outputData
    }
}

struct MemoryBlock
{
    var block : [UInt8]
    
    init(_ array : [UInt8])
    {
        self.block = array
    }
    
    init(_ slice: ArraySlice<UInt8>)
    {
        self.block = [UInt8](slice)
    }
}

func ^= (inout lhs : MemoryBlock, other : MemoryBlock)
{
    precondition(lhs.block.count == other.block.count)
    
    for i in 0..<lhs.block.count {
        lhs.block[lhs.block.startIndex + i] ^= other.block[other.block.startIndex + i]
    }
}
