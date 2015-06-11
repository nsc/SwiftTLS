//
//  DataBuffer.swift
//  Chat
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
    
    init(_ streamable : Streamable)
    {
        buffer = []
        var s = self
        streamable.writeTo(&s)
    }
    
    func write(data : [UInt8]) {
        buffer.extend(data)
    }
    
}

extension ExtensibleCollectionType where Generator.Element == UInt8
{
    mutating func write(data : [UInt8]) {
        self.extend(data)
    }
}

class BinaryInputStream : InputStreamType
{
    private var index = 0
    private var data : [UInt8]
    private var length : Int
    
    init(data : [UInt8])
    {
        self.data = data
        self.length = data.count
    }

    func read(count count: Int) -> [UInt8]? {
        if index + count <= self.length {
            let s = data[index..<index + count]
            index += count
            
            return [UInt8](s)
        }
        
        return nil
    }
}
