//
//  AESTests.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 15.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class AESTests: XCTestCase {

    func test_aes128encrypt_withExampleVector_givesCorrectOutput() {
        let key: [UInt8]   = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        let input: [UInt8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        
        var output = [UInt8](repeating: 0, count: 16)

        let aes = AES(key: key, bitSize: .aes128, encrypt: true)
        
        self.measure {
            for _ in 0..<100 {
                aes.update(indata: input, outdata: &output)
            }
        }
        /*
        let cipher = BlockCipher.encryptionBlockCipher(.aes128, mode: .cbc, key: key, IV: [])!
        let inputBlock = MemoryBlock(input)
        var outputBlock = MemoryBlock(output)
        self.measure {
            for _ in 0..<100 {
                _ = cipher.cryptorUpdate(inputBlock: inputBlock, outputBlock: &outputBlock)
            }
        }
        output = outputBlock.block
        */
        XCTAssert(output == [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a])
    }

    func test_aes128decrypt_withExampleVector_givesCorrectOutput() {
        let key: [UInt8]   = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        let input: [UInt8] = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
        
        let aes = AES(key: key, bitSize: .aes128, encrypt: false)
        
        var output = [UInt8](repeating: 0, count: 16)
        aes.update(indata: input, outdata: &output)
        
        XCTAssert(output == [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    }

}
