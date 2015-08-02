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
    var clientVersion : TLSProtocolVersion
    var random : Random
    var sessionID : SessionID?
    var rawCipherSuites : [UInt16]
    var cipherSuites : [CipherSuite] {
        get {
            var cipherSuites = [CipherSuite]()
            for rawCipherSuite in rawCipherSuites {
                if let cipherSuite = CipherSuite(rawValue: rawCipherSuite) {
                    cipherSuites.append(cipherSuite)
                }
            }
            
            return cipherSuites
        }
        
        set {
            rawCipherSuites = newValue.map {$0.rawValue}
        }
    }
    
    var compressionMethods : [CompressionMethod]
    
    init(clientVersion : TLSProtocolVersion, random : Random, sessionID : SessionID?, cipherSuites : [CipherSuite], compressionMethods : [CompressionMethod])
    {
        self.clientVersion = clientVersion
        self.random = random
        self.sessionID = sessionID
        self.rawCipherSuites = []
        self.compressionMethods = compressionMethods
        
        super.init(type: .Handshake(.ClientHello))
        
        self.cipherSuites = cipherSuites
    }
    
    required init?(inputStream : InputStreamType)
    {
        guard
            let (type, _) = TLSHandshakeMessage.readHeader(inputStream) where type == TLSHandshakeType.ClientHello,
            let major : UInt8? = inputStream.read(),
            let minor : UInt8? = inputStream.read(),
            let clientVersion = TLSProtocolVersion(major: major!, minor: minor!),
            let random = Random(inputStream: inputStream),
            let sessionIDSize : UInt8 = inputStream.read() where sessionIDSize > 0,
            let rawSessionID : [UInt8] = inputStream.read(count: Int(sessionIDSize)),
            let cipherSuitesSize : UInt16 = inputStream.read(),
            let rawCipherSuitesRead : [UInt16] = inputStream.read(count: Int(cipherSuitesSize) / sizeof(UInt16)),
            let compressionMethodsSize : UInt8 = inputStream.read(),
            let rawCompressionMethods : [UInt8] = inputStream.read(count: Int(compressionMethodsSize))
        else {
            
            self.clientVersion = TLSProtocolVersion.TLS_v1_0
            self.random = Random()
            self.sessionID = nil
            self.rawCipherSuites = []
            self.compressionMethods = []
            
            super.init(type: .Handshake(.ClientHello))
            
            return nil
        }
        
        self.clientVersion = clientVersion
        self.random = random
        self.sessionID = SessionID(sessionID: rawSessionID)
        
        self.rawCipherSuites = rawCipherSuitesRead
        self.compressionMethods = rawCompressionMethods.map {CompressionMethod(rawValue: $0)!}
        
        super.init(type: .Handshake(.ClientHello))
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
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
        
        buffer.write(UInt16(rawCipherSuites.count * sizeof(UInt16)))
        buffer.write( rawCipherSuites)
        
        buffer.write(UInt8(compressionMethods.count))
        buffer.write(compressionMethods.map { $0.rawValue})
        
        let data = buffer.buffer
        
        self.writeHeader(type: .ClientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
