//
//  TLSHandshake.swift
//  Chat
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSHandshakeMessage : TLSMessage
{
    var rawHandshakeMessageData : [UInt8]?
    
    var handshakeType : TLSHandshakeType {
        get {
            switch (self.type)
            {
            case .Handshake(let handshakeType):
                return handshakeType
            default:
                assert(false)
                fatalError("")
            }
        }
    }
    
    class func handshakeMessageFromData(data : [UInt8], context: TLSContext) -> TLSHandshakeMessage? {
        guard let (handshakeType, _) = readHeader(BinaryInputStream(data)) else {
            return nil
        }
            
        var message : TLSHandshakeMessage? = nil
        
        switch (handshakeType)
        {
        case .ClientHello:
            message = TLSClientHello(inputStream: BinaryInputStream(data), context: context)
            
        case .ServerHello:
            message = TLSServerHello(inputStream: BinaryInputStream(data), context: context)
            
        case .Certificate:
            message = TLSCertificateMessage(inputStream: BinaryInputStream(data), context: context)
            
        case .ServerHelloDone:
            message = TLSServerHelloDone(inputStream: BinaryInputStream(data), context: context)
            
        case .ServerKeyExchange:
            message = TLSServerKeyExchange(inputStream: BinaryInputStream(data), context: context)
            
        case .ClientKeyExchange:
            message = TLSClientKeyExchange(inputStream: BinaryInputStream(data), context: context)
            
        case .Finished:
            message = TLSFinished(inputStream: BinaryInputStream(data), context: context)
            
        default:
            fatalError("Unsupported handshake message")
        }
        
        if let message = message {
            message.rawHandshakeMessageData = data
            return message
        }
        
        return nil
    }
    
    internal func writeHeader<Target : OutputStreamType>(type type : TLSHandshakeType, bodyLength: Int, inout target: Target)
    {
        target.write(type.rawValue)
    
        target.write(UInt8((bodyLength >> 16) & 0xff))
        target.write(UInt8((bodyLength >>  8) & 0xff))
        target.write(UInt8((bodyLength >>  0) & 0xff))
    }
    
    class func readHeader(inputStream : InputStreamType) -> (type: TLSHandshakeType, bodyLength: Int)? {
        if  let type : UInt8 = inputStream.read(),
            handshakeType = TLSHandshakeType(rawValue: type),
            let bodyLength = inputStream.readUInt24()
        {
            return (handshakeType, bodyLength)
        }
        
        return nil
    }
    
    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
    }
}

class SessionID : Streamable
{
    static let MaximumSessionIDLength = 32

    let sessionID : [UInt8]
    init(sessionID: [UInt8])
    {
        self.sessionID = sessionID
    }
    
    required init?(inputStream : InputStreamType)
    {
        if let length : UInt8 = inputStream.read() {
            if let sessionID : [UInt8] = inputStream.read(count: Int(length)) {
                self.sessionID = sessionID
                return
            }
        }
        
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        target.write(UInt8(sessionID.count))
        target.write(sessionID)
    }
}

