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
        
        super.init(type: .handshake(.finished))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard
            let (type, _) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.finished,
            let verifyData : [UInt8] = inputStream.read(count: 12)
        else {
            return nil
        }
        
        self.verifyData = verifyData
        super.init(type: .handshake(.finished))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        let data = DataBuffer()
        data.write(self.verifyData)
        
        self.writeHeader(type: .finished, bodyLength: data.buffer.count, target: &target)
        target.write(data.buffer)
    }
}
