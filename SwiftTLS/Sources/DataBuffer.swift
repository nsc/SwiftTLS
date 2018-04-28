//
//  DataBuffer.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class DataBuffer : OutputStreamType
{
    var buffer : [UInt8]
 
    init()
    {
        buffer = []
    }
    
//    init(_ streamable : Streamable)
//    {
//        buffer = []
//        var s = self
//        streamable.writeTo(&s)
//    }
    
    func write(_ data : [UInt8]) {
        buffer.append(contentsOf: data)
    }
    
}

extension Array: OutputStreamType where Element == UInt8
{
    init(_ streamable: Streamable, context: TLSConnection? = nil)
    {
        self.init()
        
        streamable.writeTo(&self, context: context)
    }
    
    mutating public func write(_ data: [UInt8]) {
        self.append(contentsOf: data)
    }
}

extension RangeReplaceableCollection where Iterator.Element == UInt8
{
    mutating func write(_ data : [UInt8]) {
        self.append(contentsOf: data)
    }
}

class BinaryInputStream : InputStreamType
{
    var bytesRead: Int

    private var index = 0
    private var data : [UInt8]
    private var length : Int
    
    init(_ data : [UInt8])
    {
        self.data = data
        self.length = data.count
        self.bytesRead = 0
    }

    func read(count: Int) -> [UInt8]? {
        if index + count <= self.length {
            let s = data[index..<index + count]
            index += count
            bytesRead = index
            
            return [UInt8](s)
        }
        
        return nil
    }
}
