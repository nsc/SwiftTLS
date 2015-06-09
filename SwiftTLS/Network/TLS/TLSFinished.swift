//
//  TLSFinished.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 08/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSFinished : TLSHandshakeMessage
{
    var verifyData : [UInt8]
    
    init(verifyData : [UInt8])
    {
        self.verifyData = verifyData
        
        super.init(type: .Handshake(.Finished))
    }
    
    required init?(inputStream : InputStreamType)
    {
        let (type, _) = TLSHandshakeMessage.readHeader(inputStream)
        
        if let t = type {
            if t == TLSHandshakeType.Finished {
                if let verifyData : [UInt8] = read(inputStream, length: 12) {
                    self.verifyData = verifyData
                    super.init(type: .Handshake(.Finished))
                    return
                }
            }
        }
        
        self.verifyData = []
        super.init(type: .Handshake(.Finished))
    }
    
    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        let data = DataBuffer()
        write(data, data: self.verifyData)
        
        self.writeHeader(type: .Finished, bodyLength: data.buffer.count, target: &target)
        target.write(data.buffer)
    }
}
