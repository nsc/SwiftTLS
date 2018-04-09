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
        super.init(type: .handshake(.serverHelloDone))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.serverHelloDone && bodyLength == 0
        else {
            return nil
        }
        
        super.init(type: .handshake(.serverHelloDone))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        self.writeHeader(type: .serverHelloDone, bodyLength: 0, target: &target)
    }
}
