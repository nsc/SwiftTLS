//
//  SHA256.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 14.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

extension UnsignedInteger {
    func rotr(_ n: Int) -> Self {
        return (self >> n) | (self << (bitWidth - n))
    }
    
    func rotl(_ n: Int) -> Self {
        return (self << n) | (self >> (bitWidth - n))
    }

    func shr(_ n: Int) -> Self {
        return self >> n
    }
    
    func b() {
    }
}

private func Ch(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
    return (x & y) ^ (~x & z)
}

private func Maj(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
    return (x & y) ^ (x & z) ^ (y & z)
}

private func Sigma0(_ x: UInt32) -> UInt32 {
    return x.rotr(2) ^ x.rotr(13) ^ x.rotr(22)
}

private func Sigma1(_ x: UInt32) -> UInt32 {
    return x.rotr(6) ^ x.rotr(11) ^ x.rotr(25)
}

private func sigma0(_ x: UInt32) -> UInt32 {
    return x.rotr(7) ^ x.rotr(18) ^ x.shr(3)
}

private func sigma1(_ x: UInt32) -> UInt32 {
    return x.rotr(17) ^ x.rotr(19) ^ x.shr(10)
}

private let K: [UInt32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

class SHA256 : Hash {
    private var H: (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32)
    private var nextMessageBlock: [UInt8] = []
    private var messageLength = 0
    
    required init() {
        self.H = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    }
    
    fileprivate init(H: (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32)) {
        self.H = H
    }
    
    static func hash(_ m: [UInt8]) -> [UInt8] {
        let sha = self.init()
        sha.update(m)
        return sha.finalize()
    }
    
    private func updateWithBlock(_ m: [UInt8]) {
        var m = m
        var W = [UInt32](repeating: 0, count: 64)
        
        var a = H.0
        var b = H.1
        var c = H.2
        var d = H.3
        var e = H.4
        var f = H.5
        var g = H.6
        var h = H.7
        
        let blockLength = type(of: self).blockLength

        m.withUnsafeMutableBufferPointer {
            let M = UnsafeRawPointer($0.baseAddress!).bindMemory(to: UInt32.self, capacity: blockLength/4)
            
            var T1: UInt32
            var T2: UInt32
            
            for t in 0..<64 {
                W[t] = (t < 16) ? M[t].byteSwapped : sigma1(W[t-2]) &+ W[t-7] &+ sigma0(W[t-15]) &+ W[t-16]
                
                T1 = h &+ Sigma1(e) &+ Ch(e, f, g) &+ K[t] &+ W[t]
                T2 = Sigma0(a) &+ Maj(a, b, c)
                h = g
                g = f
                f = e
                e = d &+ T1
                d = c
                c = b
                b = a
                a = T1 &+ T2
            }
        }
        
        H.0 = a &+ H.0
        H.1 = b &+ H.1
        H.2 = c &+ H.2
        H.3 = d &+ H.3
        H.4 = e &+ H.4
        H.5 = f &+ H.5
        H.6 = g &+ H.6
        H.7 = h &+ H.7
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
            H.4.bigEndianBytes +
            H.5.bigEndianBytes +
            H.6.bigEndianBytes +
            H.7.bigEndianBytes
        )
    }
    
    static func padMessage(_ messageBlock: inout [UInt8], blockLength: Int, messageLength: Int) {
        // pad the message
        var paddingBytes = 55 - messageBlock.count
        if paddingBytes < 0 {
            paddingBytes += blockLength
        }

        messageBlock.append(0x80)
        messageBlock.append(contentsOf: [UInt8](repeating: 0, count: paddingBytes))
        messageBlock.append(contentsOf: UInt64(messageLength * 8).bigEndianBytes)
    }
}

class SHA224 : SHA256
{
    required init()
    {
        super.init(H: (0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4))
    }
    
    override func finalize() -> [UInt8] {
        return [UInt8](super.finalize().prefix(224/8))
    }
}
