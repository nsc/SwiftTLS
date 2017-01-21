//
//  TLSMessage.swift
//
//  Created by Nico Schmidt on 16.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSHandshakeType : UInt8 {
    // TLS 1.0
    case helloRequest = 0
    case clientHello = 1
    case serverHello = 2
    case certificate = 11
    case certificateRequest = 13
    case certificateVerify = 15
    case finished = 20

    // TLS 1.0 - 1.2 only, not in TLS 1.3
    case serverKeyExchange = 12
    case serverHelloDone = 14
    case clientKeyExchange = 16
    case certificateURL = 21
    case certificateStatus = 22
    
    // new in TLS 1.3
    case newSessionTicket = 4           // TLS 1.3
    case endOfEarlyData = 5             // TLS 1.3
    case helloRetryRequest = 6          // TLS 1.3
    case encryptedExtensions = 8        // TLS 1.3
    case keyUpdate = 24                 // TLS 1.3
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
