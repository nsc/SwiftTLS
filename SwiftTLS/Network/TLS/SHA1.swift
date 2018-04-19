//
//  SHA1.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 16.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

private func Ch(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
    return (x & y) ^ (~x & z)
}

private func Parity(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
    return x ^ y ^ z
}

private func Maj(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
    return (x & y) ^ (x & z) ^ (y & z)
}

private let K0: UInt32 = 0x5a827999
private let K1: UInt32 = 0x6ed9eba1
private let K2: UInt32 = 0x8f1bbcdc
private let K3: UInt32 = 0xca62c1d6

class SHA1 : Hash {
    private var H: (UInt32, UInt32, UInt32, UInt32, UInt32)
    private var nextMessageBlock: [UInt8] = []
    private var messageLength = 0
    
    init() {
        H = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
    }
    
    static func hash(_ m: [UInt8]) -> [UInt8] {
        let sha1 = SHA1()
        sha1.update(m)
        return sha1.finalize()
    }
    
    private func updateWithBlock(_ m: [UInt8]) {
        var m = m
        var W = [UInt32](repeating: 0, count: 80)
        
        var a = H.0
        var b = H.1
        var c = H.2
        var d = H.3
        var e = H.4
        
        let blockLength = type(of: self).blockLength

        m.withUnsafeMutableBufferPointer {
            let M = UnsafeRawPointer($0.baseAddress!).bindMemory(to: UInt32.self, capacity: blockLength/4)
            
            var T: UInt32
            
            for t in 0..<80 {
                W[t] = (t < 16) ? M[t].byteSwapped : (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]).rotl(1)
                
                let ft: UInt32
                let Kt: UInt32
                switch t {
                case 0..<20:
                    ft = Ch(b, c, d)
                    Kt = K0
                case 20..<40:
                    ft = Parity(b, c, d)
                    Kt = K1
                case 40..<60:
                    ft = Maj(b, c, d)
                    Kt = K2
                case 60..<80:
                    ft = Parity(b, c, d)
                    Kt = K3
                default:
                    fatalError("The compiler was right")
                    break
                }
                
                T = a.rotl(5) &+ ft &+ e &+ Kt &+ W[t]
                e = d
                d = c
                c = b.rotl(30)
                b = a
                a = T
            }
        }
        
        H.0 = a &+ H.0
        H.1 = b &+ H.1
        H.2 = c &+ H.2
        H.3 = d &+ H.3
        H.4 = e &+ H.4
    }
    
    static var blockLength: Int {
        return 512/8
    }
    
    func update(_ m: [UInt8]) {
        let blockLength = type(of: self).blockLength

        nextMessageBlock.append(contentsOf: m)
        
        messageLength += m.count
        
        while nextMessageBlock.count >= blockLength {
            let messageBlock = [UInt8](nextMessageBlock.prefix(blockLength))
            nextMessageBlock.removeFirst(blockLength)
            updateWithBlock(messageBlock)
        }
    }
    
    func finalize() -> [UInt8] {
        let blockLength = type(of: self).blockLength
        
        precondition(nextMessageBlock.count <= blockLength)
        
        if nextMessageBlock.count < blockLength {
            SHA256.padMessage(&nextMessageBlock, blockLength: blockLength, messageLength: messageLength)
            
            if nextMessageBlock.count > blockLength {
                let messageBlock = [UInt8](nextMessageBlock.prefix(blockLength))
                nextMessageBlock.removeFirst(blockLength)
                updateWithBlock(messageBlock)
            }
        }
        
        updateWithBlock(nextMessageBlock)
        nextMessageBlock = []
        
        return (
            H.0.bigEndianBytes +
                H.1.bigEndianBytes +
                H.2.bigEndianBytes +
                H.3.bigEndianBytes +
                H.4.bigEndianBytes
        )
    }
}

