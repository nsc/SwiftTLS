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
        let key = TLSRandomBytes(16)
        let iv  = TLSRandomBytes(16)
        
        var data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32] as [UInt8]
        
        let blockLength = 16
        let paddingLength = blockLength - ((data.count) % blockLength)
        if paddingLength != 0 {
            let padding = [UInt8](count: paddingLength, repeatedValue: UInt8(paddingLength - 1))
            
            data.appendContentsOf(padding)
        }

        print(data)
        
        let encryptor = BlockCipher.encryptionBlockCipher(.AES128, mode: .CBC, key: key, IV: iv)!
        
        let cipherText = encryptor.update(data: data, key: key, IV: nil)!
        print(cipherText)
        
        let decryptor = BlockCipher.decryptionBlockCipher(.AES128, mode: .CBC, key: key, IV: iv)!
        
        let plainText = decryptor.update(data: cipherText, key: key, IV: nil)!
        
        print(plainText)
        
        XCTAssert(plainText == data)
    }
}