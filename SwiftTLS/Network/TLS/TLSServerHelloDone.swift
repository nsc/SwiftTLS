//
//  TLSServerHelloDone.swift
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
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream) where type == TLSHandshakeType.ServerHelloDone && bodyLength == 0
        else {
            return nil
        }
        
        super.init(type: .Handshake(.ServerHelloDone))
    }
    
    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        self.writeHeader(type: .ServerHelloDone, bodyLength: 0, target: &target)
    }
}
