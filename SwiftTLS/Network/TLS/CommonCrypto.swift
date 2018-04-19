//
//  CommonCrypto.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 19.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import CommonCrypto

class CommonCryptoCryptor : Cryptor {
    let cryptor: CCCryptorRef
    private let blockSize: Int
    init(_ cryptor: CCCryptorRef, blockSize: Int) {
        self.cryptor = cryptor
        self.blockSize = blockSize
    }
    
    func update(inputBlock: MemoryBlock, outputBlock: inout MemoryBlock) -> Bool {
        var outputDataWritten: Int = 0
        let blockSize = self.blockSize
        precondition(blockSize == inputBlock.block.count)
        
        var inputBlock = inputBlock
        let status = Int(CCCryptorUpdate(self.cryptor, &inputBlock.block, blockSize, &outputBlock.block, blockSize, &outputDataWritten))
        
        return status == kCCSuccess
    }
    
    func reset(iv: [UInt8]) {
        var iv = iv
        CCCryptorReset(self.cryptor, &iv)
    }
}

extension BlockCipher {
    private class func CCCipherAlgorithmForCipherAlgorithm(_ cipherAlgorithm : CipherAlgorithm) -> CCAlgorithm?
    {
        switch (cipherAlgorithm)
        {
        case .aes128, .aes256:
            return CCAlgorithm(kCCAlgorithmAES)
            
        case .null:
            return nil
        }
    }
    
    class func encryptionBlockCipher(_ cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8]) -> BlockCipher?
    {
        guard let algorithm = CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm) else { return nil }
        
        var encryptor : CCCryptorRef? = nil
        
        var key = key
        
        let status = Int(CCCryptorCreate(CCOperation(kCCEncrypt), algorithm, UInt32(kCCOptionECBMode), &key, key.count, nil, &encryptor))
        if status != kCCSuccess {
            return nil
        }
        
        let cryptor = CommonCryptoCryptor(encryptor!, blockSize: cipherAlgorithm.blockSize)
        let cipher = BlockCipher(encrypt: true, cryptor: cryptor, mode: mode, cipher: cipherAlgorithm)
        
        return cipher
    }
    
    class func decryptionBlockCipher(_ cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8]) -> BlockCipher?
    {
        guard let algorithm = CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm) else { return nil }
        
        var decryptor : CCCryptorRef? = nil
        
        var key = key
        let operation = (mode == .gcm) ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        let status = Int(CCCryptorCreate(operation, algorithm, UInt32(kCCOptionECBMode), &key, key.count, nil, &decryptor))
        if status != kCCSuccess {
            return nil
        }
        
        let cryptor = CommonCryptoCryptor(decryptor!, blockSize: cipherAlgorithm.blockSize)
        let cipher = BlockCipher(encrypt: false, cryptor: cryptor, mode: mode, cipher: cipherAlgorithm)
        
        return cipher
    }
}

func HMAC_MD5(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgMD5), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}

func HMAC_SHA1(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA1), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}

func HMAC_SHA256(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA256), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}

func HMAC_SHA384(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA384), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}

func HMAC_SHA512(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA512), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}

func Hash_MD5(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_MD5(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}

func Hash_SHA1(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA1(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}

func Hash_SHA224(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA224(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}

func Hash_SHA256(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA256(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}

func Hash_SHA384(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA384(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}

func Hash_SHA512(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA512(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}

