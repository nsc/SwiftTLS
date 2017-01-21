//
//  TLSServerHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServerHello : TLSHandshakeMessage
{
    var version : TLSProtocolVersion
    var random : Random
    var sessionID : TLSSessionID?
    var cipherSuite : CipherSuite
    var compressionMethod : CompressionMethod?
    
    var extensions : [TLSHelloExtension] = []

    init(serverVersion : TLSProtocolVersion, random : Random, sessionID : TLSSessionID?, cipherSuite : CipherSuite, compressionMethod : CompressionMethod = .null)
    {
        self.version = serverVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
        self.compressionMethod = compressionMethod
        
        super.init(type: .handshake(.serverHello))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.serverHello,
            let major : UInt8 = inputStream.read(),
            let minor : UInt8 = inputStream.read(),
            let random = Random(inputStream: inputStream)
        else {
            return nil
        }
        
        self.version = TLSProtocolVersion(major: major, minor: minor)
        self.random = random

        var bytesLeft = bodyLength - 34
        if self.version < TLSProtocolVersion.v1_3 {
            guard
                let sessionIDSize : UInt8 = inputStream.read(),
                let rawSessionID : [UInt8] = inputStream.read(count: Int(sessionIDSize)),
                let rawCiperSuite : UInt16 = inputStream.read(), (CipherSuite(rawValue: rawCiperSuite) != nil),
                let rawCompressionMethod : UInt8 = inputStream.read(), (CompressionMethod(rawValue: rawCompressionMethod) != nil)
                else {
                    return nil
            }
            bytesLeft -= 1 + Int(sessionIDSize)
            bytesLeft -= 3

            self.sessionID = TLSSessionID(rawSessionID)
            self.cipherSuite = CipherSuite(rawValue: rawCiperSuite)!
            self.compressionMethod = CompressionMethod(rawValue: rawCompressionMethod)!

        }
        else {
            // TLS 1.3
            guard let rawCiperSuite : UInt16 = inputStream.read(), (CipherSuite(rawValue: rawCiperSuite) != nil) else {
                return nil
            }
            bytesLeft -= 2
            
            self.cipherSuite = CipherSuite(rawValue: rawCiperSuite)!
        }
        
        if bytesLeft > 0 {
            if let extensions = TLSReadHelloExtensions(from: inputStream, length: bytesLeft, helloType: .serverHello) {
                self.extensions = extensions
            }
        }

        super.init(type: .handshake(.serverHello))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        var buffer = DataBuffer()
        
        buffer.write(self.version.rawValue)
        
        random.writeTo(&buffer)
        
        
        if self.version < TLSProtocolVersion.v1_3 {
            if let session_id = self.sessionID {
                session_id.writeTo(&buffer)
            }
            else {
                buffer.write(UInt8(0))
            }
        }
        
        buffer.write(self.cipherSuite.rawValue)
        
        if self.version < TLSProtocolVersion.v1_3 {
            buffer.write(self.compressionMethod!.rawValue)
        }
        
        TLSWriteHelloExtensions(&buffer, extensions: self.extensions)

        let data = buffer.buffer
        
        self.writeHeader(type: .serverHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
