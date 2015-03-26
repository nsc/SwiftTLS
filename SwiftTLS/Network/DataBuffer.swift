//
//  DataBuffer.swift
//  Chat
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class DataBuffer : BinaryOutputStreamType
{
    var buffer : [UInt8]
 
    init()
    {
        buffer = []
    }
    
    init(_ streamable : BinaryStreamable)
    {
        buffer = []
        var s = self
        streamable.writeTo(&s)
    }
    
    func write(data : [UInt8]) {
        buffer.extend(data)
    }
    
    func write(data : [UInt16]) {
        for a in data {
            write(a)
        }
    }
    
    func write(data : UInt8) {
        buffer.append(data)
    }
    
    func write(data : UInt16) {
        buffer.append(UInt8(data >> 8))
        buffer.append(UInt8(data & 0xff))
    }
    
    func write(data : UInt32) {
        buffer.append(UInt8((data >> 24) & 0xff))
        buffer.append(UInt8((data >> 16) & 0xff))
        buffer.append(UInt8((data >>  8) & 0xff))
        buffer.append(UInt8((data >>  0) & 0xff))
    }
}

class BinaryInputStream : BinaryInputStreamType
{
    private var index = 0
    private var data : [UInt8]
    private var length : Int
    init(data : [UInt8])
    {
        self.data = data
        self.length = data.count
    }
    
    func read() -> UInt8? {
        if index + 1 <= length {
            var a : UInt8 = data[index]
            index += 1
            
            return a
        }
        
        return nil
    }

    func read() -> UInt16? {
        if index + sizeof(UInt16) <= length {
            var s = data[index..<index + sizeof(UInt16)]
            index += sizeof(UInt16)
            
            return UInt16(s[0]) << 8 + UInt16(s[1])
        }
        
        return nil
    }
    
    func read() -> UInt32? {
        if index + sizeof(UInt32) <= length {
            var s = data[index..<index + sizeof(UInt32)]
            index += sizeof(UInt32)
            
            var a = s[0]
            var b = s[0]
            var c = s[0]
            var d = s[0]
            
            return UInt32(a) << 24 + UInt32(b) << 16 + UInt32(c) << 8 + UInt32(d)
        }
        
        return nil

    }
    
    func read(length: Int) -> [UInt8]? {
        if index + length <= self.length {
            var s = data[index..<index + length]
            index += length
            
            return [UInt8](s)
        }
        
        return nil
    }

    func read(length: Int) -> [UInt16]? {
        if index + length * sizeof(UInt16) <= self.length {
            var s = data[index..<index + length * sizeof(UInt16)]
            index += length * sizeof(UInt16)
            
            var buffer = [UInt16](count:length, repeatedValue: 0)
            for var i = 0; i < length; ++i {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }
}
