//
//  TLSServerHello.swift
//  Chat
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServerHello : TLSHandshakeMessage
{
    var version : TLSProtocolVersion
    var random : Random
    var sessionID : SessionID?
    var cipherSuite : CipherSuite
    var compressionMethod : CompressionMethod
    
    init(serverVersion : TLSProtocolVersion, random : Random, sessionID : SessionID?, cipherSuite : CipherSuite, compressionMethod : CompressionMethod)
    {
        self.version = serverVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuite = cipherSuite
        self.compressionMethod = compressionMethod
        
        super.init(type: .Handshake(.ServerHello))
    }
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard
            let (type, _) = TLSHandshakeMessage.readHeader(inputStream) where type == TLSHandshakeType.ServerHello,
            let major : UInt8 = inputStream.read(),
            let minor : UInt8 = inputStream.read() where (TLSProtocolVersion(major: major, minor: minor) != nil),
            let random = Random(inputStream: inputStream),
            let sessionIDSize : UInt8 = inputStream.read(),
            let rawSessionID : [UInt8] = inputStream.read(count: Int(sessionIDSize)),
            let rawCiperSuite : UInt16 = inputStream.read() where (CipherSuite(rawValue: rawCiperSuite) != nil),
            let rawCompressionMethod : UInt8 = inputStream.read() where (CompressionMethod(rawValue: rawCompressionMethod) != nil)
        else {
            return nil
        }
        
        self.version = TLSProtocolVersion(major: major, minor: minor)!
        self.random = random
        self.sessionID = SessionID(sessionID: rawSessionID)
        self.cipherSuite = CipherSuite(rawValue: rawCiperSuite)!
        self.compressionMethod = CompressionMethod(rawValue: rawCompressionMethod)!
        
        super.init(type: .Handshake(.ServerHello))
    }
    
    override func writeTo<Target : OutputStreamType>(inout target: Target)
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
        
        let data = buffer.buffer
        
        self.writeHeader(type: .ServerHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
