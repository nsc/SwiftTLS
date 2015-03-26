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

            default:
                fatalError("Unsupported handshake message")
            }
        }
        
        return nil
    }
    
    internal func writeHeader<Target : BinaryOutputStreamType>(#type : TLSHandshakeType, bodyLength: Int, inout target: Target)
    {
        target.write(type.rawValue)
    
        target.write(UInt8((bodyLength >> 16) & 0xff))
        target.write(UInt8((bodyLength >>  8) & 0xff))
        target.write(UInt8((bodyLength >>  0) & 0xff))
    }
    
    internal class func readHeader(inputStream : BinaryInputStreamType) -> (type: TLSHandshakeType?, bodyLength: Int?) {
        if  let type : UInt8 = inputStream.read(),
            handshakeType = TLSHandshakeType(rawValue: type),
            let bodyLength = readUInt24(inputStream)
        {
            return (handshakeType, bodyLength)
        }
        
        return (nil, nil)
    }
    
    override func writeTo<Target : BinaryOutputStreamType>(inout target: Target)
    {
    }
}

class SessionID : BinaryStreamable
{
    static let MaximumSessionIDLength = 32

    let sessionID : [UInt8]
    init(sessionID: [UInt8])
    {
        self.sessionID = sessionID
    }
    
    func writeTo<Target : BinaryOutputStreamType>(inout target: Target) {
        target.write(UInt8(sessionID.count))
        target.write(sessionID)
    }
}

