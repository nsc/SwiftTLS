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
    private var _IV : [UInt8]!
    
    var IV : [UInt8] {
        get {
            return _IV
        }
        set {
            _IV = newValue
            CCCryptorReset(self.cryptor, &_IV)
        }
    }
    
    private init(cryptor : CCCryptorRef)
    {
        self.cryptor = cryptor
    }
    
    private class func CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm : CipherAlgorithm) -> CCAlgorithm?
    {
        switch (cipherAlgorithm)
        {
        case .AES:
            return CCAlgorithm(kCCAlgorithmAES)
            
        case .TRIPLE_DES:
            return CCAlgorithm(kCCAlgorithm3DES)
            
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
        let status = Int(CCCryptorCreate(CCOperation(kCCEncrypt), algorithm, 0, &key, key.count, &IV, &encryptor))
        if status != kCCSuccess {
            return nil
        }

        let cipher = BlockCipher(cryptor: encryptor)
        
        return cipher
    }
    
    class func decryptionBlockCipher(cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8], IV : [UInt8]) -> BlockCipher?
    {
        guard let algorithm = CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm) else { return nil }
        
        var encryptor : CCCryptorRef = nil
        
        var key = key
        var IV = IV
        let status = Int(CCCryptorCreate(CCOperation(kCCDecrypt), algorithm, 0, &key, key.count, &IV, &encryptor))
        if status != kCCSuccess {
            return nil
        }
        
        let cipher = BlockCipher(cryptor: encryptor)
        
        return cipher
    }

    func update(data data : [UInt8], key : [UInt8], IV : [UInt8]?) -> [UInt8]?
    {
        let outputLength : Int = CCCryptorGetOutputLength(self.cryptor, data.count, false)
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
        if let IV = IV {
            self.IV = IV
        }
        
        let status = outputData.withUnsafeMutableBufferPointer { (inout outputBuffer : UnsafeMutableBufferPointer<UInt8>) -> Int in
            var outputDataWritten : Int = 0
            
            let status = Int(CCCryptorUpdate(self.cryptor, data, data.count, outputBuffer.baseAddress, outputLength, &outputDataWritten))
            assert(outputDataWritten == outputLength)
            return status
        }
        
        if status != kCCSuccess {
            print("Error: Could not encrypt data")
            return nil
        }
        
        return outputData
    }
    
}
