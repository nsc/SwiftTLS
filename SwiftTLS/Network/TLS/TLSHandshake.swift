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
        let (handshakeType, bodyLength) = readHeader(BinaryInputStream(data: data))
            
        if  let type = handshakeType,
            let length = bodyLength
        {
            switch (type)
            {
            case .ClientHello:
                return TLSClientHello(inputStream: BinaryInputStream(data: data))

            case .ServerHello:
                return TLSServerHello(inputStream: BinaryInputStream(data: data))

            case .Certificate:
                return TLSCertificateMessage(inputStream: BinaryInputStream(data: data))
                
            case .ServerHelloDone:
                return TLSServerHelloDone(inputStream: BinaryInputStream(data: data))

            case .ClientKeyExchange:
                return TLSClientKeyExchange(inputStream: BinaryInputStream(data: data))
                
            case .Finished:
                return TLSFinished(inputStream: BinaryInputStream(data: data))
                
            default:
                fatalError("Unsupported handshake message")
            }
        }
        
        return nil
    }
    
    internal func writeHeader<Target : OutputStreamType>(#type : TLSHandshakeType, bodyLength: Int, inout target: Target)
    {
        write(target, type.rawValue)
    
        write(target, UInt8((bodyLength >> 16) & 0xff))
        write(target, UInt8((bodyLength >>  8) & 0xff))
        write(target, UInt8((bodyLength >>  0) & 0xff))
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
            if let sessionID : [UInt8] = read(inputStream, Int(length)) {
                self.sessionID = sessionID
                return
            }
        }
        
        self.sessionID = []
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        write(target, UInt8(sessionID.count))
        write(target, sessionID)
    }
}

