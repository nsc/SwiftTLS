//
//  TLSMessage.swift
//
//  Created by Nico Schmidt on 16.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSHandshakeType : UInt8 {
    case helloRequest = 0
    case clientHello = 1
    case serverHello = 2
    case certificate = 11
    case serverKeyExchange = 12
    case certificateRequest = 13
    case serverHelloDone = 14
    case certificateVerify = 15
    case clientKeyExchange = 16
    case finished = 20
    case certificateURL = 21
    case certificateStatus = 22
}

enum TLSMessageType
{
    case changeCipherSpec
    case handshake(TLSHandshakeType)
    case alert(TLSAlertLevel, TLSAlert)
    case applicationData
}

enum TLSChangeCipherSpecType : UInt8
{
    case changeCipherSpec = 1
}

class TLSMessage : Streamable
{
    let type : TLSMessageType

    var contentType : ContentType {
        get {
            let contentType : ContentType
            switch (self.type)
            {
            case .changeCipherSpec:
                contentType = .changeCipherSpec
                
            case .alert:
                contentType = .alert
                
            case .handshake:
                contentType = .handshake
                
            case .applicationData:
                contentType = .applicationData
            }

            return contentType
        }
    }
    
    init(type : TLSMessageType)
    {
        self.type = type
    }
    
    required init?(inputStream: InputStreamType, context: TLSConnection) {
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
    }
}
