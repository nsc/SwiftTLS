//
//  Streamable.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

public protocol OutputStreamType
{
    mutating func write(_ data : [UInt8])
}

public protocol InputStreamType
{
    var bytesRead: Int {get set}
    func read(count : Int) -> [UInt8]?
}

public protocol Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
}

public extension OutputStreamType
{
    private mutating func write(_ data : [UInt16]) {
        for a in data {
            self.write([UInt8(a >> 8), UInt8(a & 0xff)])
        }
    }
    
    mutating func write8(_ data: [UInt8]) {
        self.write(UInt8(data.count))
        self.write(data)
    }
    
    mutating func write16(_ data: [UInt8]) {
        self.write(UInt16(data.count))
        self.write(data)
    }
    
    mutating func write16(_ data: [UInt16]) {
        self.write(UInt16(data.count * MemoryLayout<UInt16>.size))
        self.write(data)
    }
    
    mutating func write24(_ data: [UInt8]) {
        self.writeUInt24(data.count)
        self.write(data)
    }
    
    mutating func write(_ data : UInt8) {
        self.write([data])
    }
    
    mutating func write(_ data : UInt16) {
        self.write([UInt8(data >> 8), UInt8(data & 0xff)])
    }
    
    mutating func write(_ data : UInt32) {
        self.write([UInt8((data >> 24) & 0xff), UInt8((data >> 16) & 0xff), UInt8((data >>  8) & 0xff), UInt8((data >>  0) & 0xff)])
    }
    
    mutating func write(_ data : UInt64) {
        let a = UInt8((data >> 56) & 0xff)
        let b = UInt8((data >> 48) & 0xff)
        let c = UInt8((data >> 40) & 0xff)
        let d = UInt8((data >> 32) & 0xff)
        let e = UInt8((data >> 24) & 0xff)
        let f = UInt8((data >> 16) & 0xff)
        let g = UInt8((data >>  8) & 0xff)
        let h = UInt8((data >>  0) & 0xff)
        
        self.write([a, b, c, d, e, f, g, h])
    }
    
    mutating func writeUInt24(_ value : Int)
    {
        self.write([UInt8((value >> 16) & 0xff), UInt8((value >>  8) & 0xff), UInt8((value >>  0) & 0xff)])
    }
    
    mutating func write<T: Streamable>(_ data: T) {
        data.writeTo(&self, context: nil)
    }
}

extension InputStreamType
{
    func read() -> UInt8?
    {
        if let a : [UInt8] = self.read(count: 1) {
            return a[0]
        }
        
        return nil
    }
    
    func read() -> UInt16?
    {
        if let s : [UInt8] = self.read(count: 2) {
            return UInt16(s[0]) << 8 + UInt16(s[1])
        }
        
        return nil
    }
    
    func read() -> UInt32?
    {
        if let s : [UInt8] = self.read(count: 4) {
            
            let a = UInt32(s[0])
            let b = UInt32(s[1])
            let c = UInt32(s[2])
            let d = UInt32(s[3])
            
            return a << 24 + b << 16 + c << 8 + d
        }
        
        return nil
    }
    
    func read(count: Int) -> [UInt16]?
    {
        if let s : [UInt8] = self.read(count: count * 2) {
            var buffer = [UInt16](repeating: 0, count: count)
            for i in 0 ..< count {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }
    
    func read(bytes: Int) -> [UInt16]?
    {
        let count = bytes / 2
        if let s : [UInt8] = self.read(count: bytes) {
            var buffer = [UInt16](repeating: 0, count: count)
            for i in 0 ..< count {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }
    
    func readUInt24() -> Int?
    {
        if  let a : [UInt8] = self.read(count: 3)
        {
            return Int(a[0]) << 16 + Int(a[1]) << 8 + Int(a[2])
        }
        
        return nil
    }
    
    func read8() -> [UInt8]?
    {
        guard
            let count : UInt8 = self.read(),
            let data : [UInt8] = self.read(count: Int(count))
            else {
                return nil
        }
        
        return data
    }
    
    func read16() -> [UInt8]?
    {
        guard
            let count : UInt16 = self.read(),
            let data : [UInt8] = self.read(count: Int(count))
            else {
                return nil
        }
        
        return data
    }
    
    func read8() -> [UInt16]?
    {
        guard
            let count : UInt8 = self.read(),
            let data : [UInt16] = self.read(count: Int(count) / MemoryLayout<UInt16>.size)
            else {
                return nil
        }
        
        return data
    }
    
    func read16() -> [UInt16]?
    {
        guard
            let count : UInt16 = self.read(),
            let data : [UInt16] = self.read(bytes: Int(count))
            else {
                return nil
        }
        
        return data
    }    
}
