//
//  TLSServerHelloDone.swift
//  Chat
//
//  Created by Nico Schmidt on 17.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServerHelloDone : TLSHandshakeMessage
{
    init()
    {
        super.init(type: .Handshake(.ServerHelloDone))
    }
    
    required init?(inputStream : BinaryInputStreamType)
    {
        let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream)
        
        if let t = type {
            if t == TLSHandshakeType.ServerHelloDone {
                if bodyLength > 0 {
                    super.init(type: .Handshake(.ServerHelloDone))
                    return nil
                }
            }
        }
        
        super.init(type: .Handshake(.ServerHelloDone))
    }
    
    override func writeTo<Target : BinaryOutputStreamType>(inout target: Target)
    {
        self.writeHeader(type: .ServerHelloDone, bodyLength: 0, target: &target)
    }
}
