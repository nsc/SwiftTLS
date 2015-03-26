//
//  TLSMessage.swift
//  Chat
//
//  Created by Nico Schmidt on 16.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSHandshakeType : UInt8 {
    case HelloRequest = 0
    case ClientHello = 1
    case ServerHello = 2
    case Certificate = 11
    case ServerHelloDone = 14
    case ClientKeyExchange = 16
    case Finished = 20
}

enum TLSMessageType
{
    case ChangeCipherSpec
    case Handshake(TLSHandshakeType)
    case Alert
    case ApplicationData
}

class TLSMessage : BinaryStreamable, BinaryReadable
{
    let type : TLSMessageType

    init(type : TLSMessageType)
    {
        self.type = type
    }
    
    required init?(inputStream: BinaryInputStreamType) {
        self.type = .Alert
        return nil
    }
    
    func writeTo<Target : BinaryOutputStreamType>(inout target: Target) {
    }
}