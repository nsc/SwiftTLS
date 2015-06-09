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
    
    class func handshakeMessageFromData(data : [UInt8]) -> TLSHandshakeMessage? {
        let (handshakeType, _) = readHeader(BinaryInputStream(data: data))
            
        if  let type = handshakeType
        {
            var message : TLSHandshakeMessage? = nil
            
            switch (type)
            {
            case .ClientHello:
                message = TLSClientHello(inputStream: BinaryInputStream(data: data))

            case .ServerHello:
                message = TLSServerHello(inputStream: BinaryInputStream(data: data))

            case .Certificate:
                message = TLSCertificateMessage(inputStream: BinaryInputStream(data: data))
                
            case .ServerHelloDone:
                message = TLSServerHelloDone(inputStream: BinaryInputStream(data: data))

            case .ClientKeyExchange:
                message = TLSClientKeyExchange(inputStream: BinaryInputStream(data: data))
                
            case .Finished:
                message = TLSFinished(inputStream: BinaryInputStream(data: data))
                
            default:
                fatalError("Unsupported handshake message")
            }
            
            if let message = message {
                message.rawHandshakeMessageData = data
                return message
            }
        }
        
        return nil
    }
    
    internal func writeHeader<Target : OutputStreamType>(type type : TLSHandshakeType, bodyLength: Int, inout target: Target)
    {
        write(target, data: type.rawValue)
    
        write(target, data: UInt8((bodyLength >> 16) & 0xff))
        write(target, data: UInt8((bodyLength >>  8) & 0xff))
        write(target, data: UInt8((bodyLength >>  0) & 0xff))
    }
    
    internal class func readHeader(inputStream : InputStreamType) -> (type: TLSHandshakeType?, bodyLength: Int?) {
        if  let type : UInt8 = read(inputStream),
            handshakeType = TLSHandshakeType(rawValue: type),
            let bodyLength = readUInt24(inputStream)
        {
            return (handshakeType, bodyLength)
        }
        
        return (nil, nil)
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
        if let length : UInt8 = read(inputStream) {
            if let sessionID : [UInt8] = read(inputStream, length: Int(length)) {
                self.sessionID = sessionID
                return
            }
        }
        
        self.sessionID = []
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        write(target, data: UInt8(sessionID.count))
        write(target, data: sessionID)
    }
}

