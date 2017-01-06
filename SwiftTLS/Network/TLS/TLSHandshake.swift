//
//  TLSHandshake.swift
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
            case .handshake(let handshakeType):
                return handshakeType
            default:
                assert(false)
                fatalError("")
            }
        }
    }
    
    class func handshakeMessageFromData(_ data : [UInt8], context: TLSConnection) -> (TLSHandshakeMessage?, excessData: [UInt8]?) {
        guard let (handshakeType, bodyLength) = readHeader(BinaryInputStream(data)) else {
            return (nil, nil)
        }
            
        var message : TLSHandshakeMessage? = nil
        // The header is 4 bytes long. One byte for the type and 3 bytes for the length
        let bodyData = [UInt8](data[0 ..< bodyLength + 4])
        let excessData = [UInt8](data[bodyLength + 4 ..< data.count])
        
        let inputStream = BinaryInputStream(bodyData)
        switch (handshakeType)
        {
        case .clientHello:
            message = TLSClientHello(inputStream: inputStream, context: context)
            
        case .serverHello:
            message = TLSServerHello(inputStream: inputStream, context: context)
            
        case .certificate:
            message = TLSCertificateMessage(inputStream: inputStream, context: context)
            
        case .serverHelloDone:
            message = TLSServerHelloDone(inputStream: inputStream, context: context)
            
        case .serverKeyExchange:
            message = TLSServerKeyExchange(inputStream: inputStream, context: context)
            
        case .clientKeyExchange:
            message = TLSClientKeyExchange(inputStream: inputStream, context: context)
            
        case .finished:
            message = TLSFinished(inputStream: inputStream, context: context)
            
        default:
            fatalError("Unsupported handshake message")
        }
        
        if let message = message {
            message.rawHandshakeMessageData = bodyData
            return (message, excessData)
        }
        
        return (nil, nil)
    }
    
    internal func writeHeader<Target : OutputStreamType>(type : TLSHandshakeType, bodyLength: Int, target: inout Target)
    {
        target.write(type.rawValue)
    
        target.write(UInt8((bodyLength >> 16) & 0xff))
        target.write(UInt8((bodyLength >>  8) & 0xff))
        target.write(UInt8((bodyLength >>  0) & 0xff))
    }
    
    class func readHeader(_ inputStream : InputStreamType) -> (type: TLSHandshakeType, bodyLength: Int)? {
        if  let type : UInt8 = inputStream.read(),
            let handshakeType = TLSHandshakeType(rawValue: type),
            let bodyLength = inputStream.readUInt24()
        {
            return (handshakeType, bodyLength)
        }
        
        return nil
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
    }
}

