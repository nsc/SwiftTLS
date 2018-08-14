//
//  TLSHandshake.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public class TLSHandshakeMessage : TLSMessage
{
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
    
    enum Result {
        case message(TLSHandshakeMessage, excessData: [UInt8]) // the message and excess data
        case notEnoughData
        case error
    }
    
    class func handshakeMessageFromData(_ data : [UInt8], context: TLSConnection) -> Result {
        guard let (handshakeType, bodyLength) = readHeader(BinaryInputStream(data)) else {
            return .notEnoughData
        }
        
        guard data.count >= bodyLength + 4 else {
            return .notEnoughData
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
            if let serverHello = TLSServerHello(inputStream: inputStream, context: context) {
                if serverHello.isHelloRetryRequest {
                    message = TLSHelloRetryRequest(serverHello)
                }
                else {
                    message = serverHello
                }
            }
            
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
            
        // TLS 1.3
        case .encryptedExtensions:
            message = TLS1_3.TLSEncryptedExtensions(inputStream: inputStream, context: context)

        case .certificateVerify:
            message = TLS1_3.TLSCertificateVerify(inputStream: inputStream, context: context)
            
        case .newSessionTicket:
            message = TLS1_3.TLSNewSessionTicket(inputStream: inputStream, context: context)

        case .endOfEarlyData:
            message = TLS1_3.TLSEndOfEarlyData(inputStream: inputStream, context: context)

        default:
            log("Error: Unsupported handshake message \(handshakeType)")
        }
        
        if let message = message {
            message.rawMessageData = bodyData
            return .message(message, excessData: excessData)
        }
        
        return .error
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
    
    override public func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        self.writeHeader(type: self.handshakeType, bodyLength: 0, target: &target)
    }
}

