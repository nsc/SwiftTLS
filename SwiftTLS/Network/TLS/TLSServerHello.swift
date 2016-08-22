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
    var compressionMethod : CompressionMethod
    
    var extensions : [TLSHelloExtension] = []

    init(serverVersion : TLSProtocolVersion, random : Random, sessionID : TLSSessionID?, cipherSuite : CipherSuite, compressionMethod : CompressionMethod)
    {
        self.version = serverVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
        self.compressionMethod = compressionMethod
        
        super.init(type: .handshake(.serverHello))
    }
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.serverHello,
            let major : UInt8 = inputStream.read(),
            let minor : UInt8 = inputStream.read(), (TLSProtocolVersion(major: major, minor: minor) != nil),
            let random = Random(inputStream: inputStream),
            let sessionIDSize : UInt8 = inputStream.read(),
            let rawSessionID : [UInt8] = inputStream.read(count: Int(sessionIDSize)),
            let rawCiperSuite : UInt16 = inputStream.read(), (CipherSuite(rawValue: rawCiperSuite) != nil),
            let rawCompressionMethod : UInt8 = inputStream.read(), (CompressionMethod(rawValue: rawCompressionMethod) != nil)
        else {
            return nil
        }
        
        self.version = TLSProtocolVersion(major: major, minor: minor)!
        self.random = random
        self.sessionID = TLSSessionID(rawSessionID)
        self.cipherSuite = CipherSuite(rawValue: rawCiperSuite)!
        self.compressionMethod = CompressionMethod(rawValue: rawCompressionMethod)!
        
        var bytesLeft = bodyLength - 34 - 3
        bytesLeft -= 1 + Int(sessionIDSize)
        
        if bytesLeft > 0 {
            if let extensions = TLSReadHelloExtensions(from: inputStream, length: bytesLeft) {
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
        
        if let session_id = self.sessionID {
            session_id.writeTo(&buffer)
        }
        else {
            buffer.write(UInt8(0))
        }
        
        buffer.write(self.cipherSuite.rawValue)
        
        buffer.write(self.compressionMethod.rawValue)
        
        TLSWriteHelloExtensions(&buffer, extensions: self.extensions)

        let data = buffer.buffer
        
        self.writeHeader(type: .serverHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
