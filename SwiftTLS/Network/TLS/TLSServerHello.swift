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
    
    required init?(inputStream : BinaryInputStreamType)
    {
        var clientVersion : TLSProtocolVersion?
        var random : Random?
        var sessionID : SessionID?
        var cipherSuite : CipherSuite?
        var compressionMethod : CompressionMethod?
        
        let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream)
        
        if let t = type {
            if t == TLSHandshakeType.ServerHello {
                
                if let major : UInt8? = inputStream.read(),
                    minor : UInt8? = inputStream.read(),
                    cv = TLSProtocolVersion(major: major!, minor: minor!)
                {
                    clientVersion = cv
                }
                
                if let r = Random(inputStream: inputStream)
                {
                    random = r
                }
                
                if  let sessionIDSize : UInt8 = inputStream.read(),
                    let rawSessionID : [UInt8] = inputStream.read(Int(sessionIDSize))
                {
                    sessionID = SessionID(sessionID: rawSessionID)
                }
                
                if  let rawCiperSuite : UInt16 = inputStream.read()
                {
                    cipherSuite = CipherSuite(rawValue: rawCiperSuite)
                }
                
                if  let rawCompressionMethod : UInt8 = inputStream.read()
                {
                    compressionMethod = CompressionMethod(rawValue: rawCompressionMethod)
                }
            }
        }
        
        if  let cv = clientVersion,
            let r = random,
            let cs = cipherSuite,
            let cm = compressionMethod
        {
            self.version = cv
            self.random = r
            self.sessionID = sessionID
            self.cipherSuite = cs
            self.compressionMethod = cm
            
            super.init(type: .Handshake(.ServerHello))
        }
        else {
            self.version = TLSProtocolVersion.TLS_v1_0
            self.random = Random()
            self.sessionID = nil
            self.cipherSuite = CipherSuite.TLS_RSA_WITH_NULL_MD5
            self.compressionMethod = CompressionMethod.NULL
            
            super.init(type: .Handshake(.ServerHello))
            
            return nil
        }
    }
    
    override func writeTo<Target : BinaryOutputStreamType>(inout target: Target)
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
        
        var data = buffer.buffer
        
        self.writeHeader(type: .ClientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
