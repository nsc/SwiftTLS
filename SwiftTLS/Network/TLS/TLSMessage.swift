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
    case ServerKeyExchange = 12
    case CertificateRequest = 13
    case ServerHelloDone = 14
    case CertificateVerify = 15
    case ClientKeyExchange = 16
    case Finished = 20
}

enum TLSMessageType
{
    case ChangeCipherSpec
    case Handshake(TLSHandshakeType)
    case Alert(TLSAlertLevel, TLSAlertDescription)
    case ApplicationData
}

enum TLSChangeCipherSpecType : UInt8
{
    case ChangeCipherSpec = 1
}

class TLSMessage : BinaryStreamable, BinaryReadable
{
    let type : TLSMessageType

    init(type : TLSMessageType)
    {
        self.type = type
    }
    
    required init?(inputStream: BinaryInputStreamType) {
        self.type = .Alert(.Warning, .CloseNotify)
        return nil
    }
    
    func writeTo<Target : BinaryOutputStreamType>(inout target: Target)
    {
    }
}