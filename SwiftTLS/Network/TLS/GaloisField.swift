//
//  GaloisField.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

struct GF2_128_Element {
    var hi : UInt64
    var lo : UInt64
    
    init() {
        hi = 0
        lo = 0
    }
    
    init(_ a : UInt) {
        hi = 0
        lo = UInt64(a)
    }
    
    init(hi : UInt64, lo : UInt64) {
        self.hi = hi
        self.lo = lo
    }
    
    init?(_ a : [UInt8]) {
        precondition(a.count == 16)
        var hi = UInt64(0)
        var lo = UInt64(0)
        a.withUnsafeBufferPointer {
            let b = UnsafeBufferPointer<UInt64>(start: UnsafePointer<UInt64>($0.baseAddress), count: 2)
            hi = b[0].bigEndian
            lo = b[1].bigEndian
        }
        
        self.hi = hi
        self.lo = lo
    }
    
    func rightshift() -> GF2_128_Element {
        let rlo : UInt64 = (lo >> 1) + ((0x1 & hi) == 0 ? 0 : 0x8000000000000000)
        let rhi : UInt64 = hi >> 1
        return GF2_128_Element(hi: rhi, lo: rlo)
    }
    
    func leftshift() -> GF2_128_Element {
        let rhi : UInt64 = (hi << 1) + ((0x8000000000000000 & lo) == 0 ? 0 : 1)
        let rlo : UInt64 = lo << 1
        return GF2_128_Element(hi: rhi, lo: rlo)
    }
    
    func isBitSet(n : Int) -> Bool {
        var n = n
        precondition(n >= 0)

        n = 127 - n
        
        if n < 64 {
            return ((UInt64(1) << UInt64(n & 0x3f)) & lo) != 0
        }
        if n < 128 {
            let shift = UInt64(n - 64)
            return (UInt64(1 << shift) & hi) != 0
        }
        
        return false
    }
    
    func asBigEndianByteArray() -> [UInt8] {
        return hi.bigEndianByteArray() + lo.bigEndianByteArray()
    }
}

func ^(x : GF2_128_Element, y : GF2_128_Element) -> GF2_128_Element {
    return GF2_128_Element(hi: x.hi ^ y.hi, lo: x.lo ^ y.lo)
}

func *(x : GF2_128_Element, y : GF2_128_Element) -> GF2_128_Element {
    let r = GF2_128_Element(hi: 0xe100000000000000, lo: 0)
    var z = GF2_128_Element(0)
    var v = x
    for i in 0..<128 {
        if y.isBitSet(i) {
            z = z ^ v
        }
        if v.isBitSet(127) {
            v = v.rightshift() ^ r
        }
        else {
            v = v.rightshift()
        }
    }
    
    return z
}

func ghashUpdate(ghash: GF2_128_Element, h: GF2_128_Element, x: [UInt8]) -> GF2_128_Element
{
    let blockSize = 16 // byte, which is 128 bit
    var countX = x.count
    
    var y = ghash
    var startIndex = 0
    var xBlock = [UInt8](count: 16, repeatedValue: 0)
    while countX > 0 {
        let length = (countX >= blockSize) ? blockSize : countX
        // copy next chunk from x to xBlock filling with zeros
        xBlock.withUnsafeMutableBufferPointer { dst in
            x.withUnsafeBufferPointer { src in
                memcpy(dst.baseAddress, src.baseAddress + startIndex, length)
                if length < blockSize {
                    memset(dst.baseAddress + length, 0, blockSize - length)
                }
            }
        }
        
        y = (y ^ GF2_128_Element(xBlock)!) * h
        
        startIndex += length
        countX -= length
    }
    
    return y
}

func ghash(h : GF2_128_Element, authData: [UInt8], x : [UInt8]) -> GF2_128_Element
{
    var y = ghashUpdate(GF2_128_Element(), h: h, x: authData)
    y = ghashUpdate(y, h: h, x: x)
    
    return (y ^ GF2_128_Element(hi: UInt64(authData.count), lo: UInt64(x.count))) * h
}
