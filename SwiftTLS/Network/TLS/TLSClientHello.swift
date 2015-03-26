//
//  TLSClientHello.swift
//  Chat
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSClientHello : TLSHandshakeMessage
{
    var clientVersion : ProtocolVersion
    var random : Random
    var sessionID : SessionID?
    var cipherSuites : [CipherSuite]
    var compressionMethods : [CompressionMethod]
    
    init(clientVersion : ProtocolVersion, random : Random, sessionID : SessionID?, cipherSuites : [CipherSuite], compressionMethods : [CompressionMethod])
    {
        self.clientVersion = clientVersion
        self.random = random
        self.sessionID = sessionID
        self.cipherSuites = cipherSuites
        self.compressionMethods = compressionMethods
        
        super.init(type: .Handshake(.ClientHello))
    }
    
    required init?(inputStream : BinaryInputStreamType)
    {
        var clientVersion : ProtocolVersion?
        var random : Random?
        var sessionID : SessionID?
        var cipherSuites : [CipherSuite]?
        var compressionMethods : [CompressionMethod]?
        
        let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream)
        
        if let t = type {
            if t == TLSHandshakeType.ClientHello {
                
                if let major : UInt8? = inputStream.read(),
                    minor : UInt8? = inputStream.read(),
                    cv = ProtocolVersion(major: major!, minor: minor!)
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
                
                if  let cipherSuitesSize : UInt16 = inputStream.read(),
                    let rawCipherSuites : [UInt16] = inputStream.read(Int(cipherSuitesSize) / sizeof(UInt16))
                {
                    cipherSuites = rawCipherSuites.map {CipherSuite(rawValue: $0)!}
                }
                
                if  let compressionMethodsSize : UInt8 = inputStream.read(),
                    let rawCompressionMethods : [UInt8] = inputStream.read(Int(compressionMethodsSize))
                {
                    compressionMethods = rawCompressionMethods.map {CompressionMethod(rawValue: $0)!}
                }
            }
        }
        
        if  let cv = clientVersion,
            let r = random,
            let cs = cipherSuites,
            let cm = compressionMethods
        {
            self.clientVersion = cv
            self.random = r
            self.sessionID = sessionID
            self.cipherSuites = cs
            self.compressionMethods = cm
            
            super.init(type: .Handshake(.ClientHello))
        }
        else {
            self.clientVersion = ProtocolVersion.TLS_v1_0
            self.random = Random()
            self.sessionID = nil
            self.cipherSuites = []
            self.compressionMethods = []
            
            super.init(type: .Handshake(.ClientHello))
            
            return nil
        }
    }
    
    override func writeTo<Target : BinaryOutputStreamType>(inout target: Target)
    {
        var buffer = DataBuffer()
        
        buffer.write(clientVersion.rawValue)
        
        random.writeTo(&buffer)
        
        if let session_id = sessionID {
            session_id.writeTo(&buffer)
        }
        else {
            buffer.write(UInt8(0))
        }
        
        buffer.write(UInt16(cipherSuites.count * sizeof(UInt16)))
        buffer.write(cipherSuites.map { $0.rawValue})
        
        buffer.write(UInt8(compressionMethods.count))
        buffer.write(compressionMethods.map { $0.rawValue})
        
        var data = buffer.buffer
        
        self.writeHeader(type: .ClientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
