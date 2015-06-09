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
    
    required init?(inputStream : InputStreamType)
    {
        var clientVersion : TLSProtocolVersion?
        var random : Random?
        var sessionID : SessionID?
        var cipherSuite : CipherSuite?
        var compressionMethod : CompressionMethod?
        
        let (type, _) = TLSHandshakeMessage.readHeader(inputStream)
        
        if let t = type {
            if t == TLSHandshakeType.ServerHello {
                
                if let major : UInt8? = read(inputStream),
                    minor : UInt8? = read(inputStream),
                    cv = TLSProtocolVersion(major: major!, minor: minor!)
                {
                    clientVersion = cv
                }
                
                if let r = Random(inputStream: inputStream)
                {
                    random = r
                }
                
                if  let sessionIDSize : UInt8 = read(inputStream),
                    let rawSessionID : [UInt8] = read(inputStream, length: Int(sessionIDSize))
                {
                    sessionID = SessionID(sessionID: rawSessionID)
                }
                
                if  let rawCiperSuite : UInt16 = read(inputStream)
                {
                    cipherSuite = CipherSuite(rawValue: rawCiperSuite)
                }
                
                if  let rawCompressionMethod : UInt8 = read(inputStream)
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
    
    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        var buffer = DataBuffer()
        
        write(buffer, data: self.version.rawValue)
        
        random.writeTo(&buffer)
        
        if let session_id = self.sessionID {
            session_id.writeTo(&buffer)
        }
        else {
            write(buffer, data: UInt8(0))
        }
        
        write(buffer, data: self.cipherSuite.rawValue)
        
        write(buffer, data: self.compressionMethod.rawValue)
        
        let data = buffer.buffer
        
        self.writeHeader(type: .ServerHello, bodyLength: data.count, target: &target)
        write(target, data: data)
    }
}
