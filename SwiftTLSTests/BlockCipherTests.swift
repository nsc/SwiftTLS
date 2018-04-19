//
//  BlockCipherTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

@testable import SwiftTLS

import XCTest

class BlockCipherTests : XCTestCase {
    func test_CBC_encryptionAndSuccessiveDecryption_works()
    {
        let key = TLSRandomBytes(count: 16)
        let iv  = TLSRandomBytes(count: 16)
        
        var data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32] as [UInt8]
        
        let blockLength = 16
        let paddingLength = blockLength - ((data.count) % blockLength)
        if paddingLength != 0 {
            let padding = [UInt8](repeating: UInt8(paddingLength - 1), count: paddingLength)
            
            data.append(contentsOf: padding)
        }

        print(data)
        
        let encryptor = BlockCipher.encryptionBlockCipher(.aes128, mode: .cbc, key: key)!
        
        let cipherText = encryptor.update(data: data, key: key, IV: iv)!
        print(cipherText)
        
        let decryptor = BlockCipher.decryptionBlockCipher(.aes128, mode: .cbc, key: key)!
        
        let plainText = decryptor.update(data: cipherText, key: key, IV: iv)!
        
        print(plainText)
        
        XCTAssert(plainText == data)
    }
    
    func UInt8ArrayFromHexString(_ string : String) -> [UInt8]
    {
        var v : UInt8 = 0
        var i = 0
        var result = [UInt8]()
        for c in string.utf8 {
            var w : UInt8 = 0
            switch c
            {
            case 0x30...0x39: w = c - 0x30
            case 0x61...0x66: w = c - 0x61 + 10
            case 0x41...0x46: w = c - 0x41 + 10
            default:
                return []
            }
            
            v += w
            if i != 0 && i % 2 != 0 {
                result.append(v)
                v = 0
            }
            
            v = v << 4
            i += 1
        }
        
        return result
    }
    
    let gcmTestVectors = [
        // test case name, key, plain text, authData, iv, cipher text, authTag
        (
            "Test Case 1",
            "00000000000000000000000000000000",
            "",
            "",
            "000000000000000000000000",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a"
        ),
        (
            "Test Case 2",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf"
        ),
        (
            "Test Case 3",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "",
            "cafebabefacedbaddecaf888",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4"
        ),
        (
            "Test Case 4",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "cafebabefacedbaddecaf888",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47"
        ),
        (
            "Test Case 5",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "cafebabefacedbad",
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb"
        ),
        (
            "Test Case 6",
            "feffe9928665731c6d6a8f9467308308",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
            "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
            "619cc5aefffe0bfa462af43c1699d050"
        )
        
        ]

    func test_GCM_encryption_works()
    {
        
        for (testCaseName, keyString, plainTextString, authDataString, ivString, expectedCipherTextString, authTagString) in gcmTestVectors
        {
            let key = UInt8ArrayFromHexString(keyString)
            let iv = UInt8ArrayFromHexString(ivString)
            let plainText = UInt8ArrayFromHexString(plainTextString)
            let expectedCipherText = UInt8ArrayFromHexString(expectedCipherTextString)
            let authData = UInt8ArrayFromHexString(authDataString)
            let authTag = UInt8ArrayFromHexString(authTagString)
            
            let encryptor = BlockCipher.encryptionBlockCipher(.aes128, mode: .gcm, key: key)!
            
            let cipherText = encryptor.update(data: plainText, authData: authData, key: key, IV: iv)!
            XCTAssert(cipherText == expectedCipherText, "\(testCaseName) failed")
            XCTAssert(encryptor.authTag! == authTag, "\(testCaseName) failed")
        }
    }

    func test_GCM_decryption_works()
    {
        
        for (testCaseName, keyString, plainTextString, authDataString, ivString, cipherTextString, authTagString) in gcmTestVectors
        {
            let key = UInt8ArrayFromHexString(keyString)
            let iv = UInt8ArrayFromHexString(ivString)
            let expectedPlainText = UInt8ArrayFromHexString(plainTextString)
            let cipherText = UInt8ArrayFromHexString(cipherTextString)
            let authData = UInt8ArrayFromHexString(authDataString)
            let authTag = UInt8ArrayFromHexString(authTagString)
            
            let encryptor = BlockCipher.decryptionBlockCipher(.aes128, mode: .gcm, key: key)!
            
            let plainText = encryptor.update(data: cipherText, authData: authData, key: key, IV: iv)!
            XCTAssert(plainText == expectedPlainText, "\(testCaseName) failed")
            XCTAssert(encryptor.authTag! == authTag, "\(testCaseName) failed")
        }
    }
}
