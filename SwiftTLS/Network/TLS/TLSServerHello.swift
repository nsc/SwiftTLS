//
//  TLSServerHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServerHello : TLSHandshakeMessage
{
    var legacyVersion : TLSProtocolVersion
    var random : Random
    var legacySessionID : TLSSessionID?
    var cipherSuite : CipherSuite
    var legacyCompressionMethod : CompressionMethod?
    
    var extensions : [TLSExtension] = []

    var version : TLSProtocolVersion {
        if self.legacyVersion < .v1_2 {
            return self.legacyVersion
        }
        else {
            guard let supportedVersions = self.extensions.filter({$0.extensionType == .supportedVersions}).first as? TLSSupportedVersionsExtension else {
                return self.legacyVersion
            }
            
            guard supportedVersions.supportedVersions.count > 0 else {
                // This is most certainly an error ... figure out what to do here
                return self.legacyVersion
            }
            
            return supportedVersions.supportedVersions.first!
        }
    }
    
    init(serverVersion : TLSProtocolVersion, random : Random, sessionID : TLSSessionID?, cipherSuite : CipherSuite, compressionMethod : CompressionMethod = .null)
    {
        self.legacyVersion = serverVersion
        self.random = random
        self.legacySessionID = sessionID
        self.cipherSuite = cipherSuite
        self.legacyCompressionMethod = compressionMethod
        
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
        
        self.legacyVersion = TLSProtocolVersion(major: major, minor: minor)
        self.random = random

        var bytesLeft = bodyLength - 34

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
        
        self.legacySessionID = TLSSessionID(rawSessionID)
        self.cipherSuite = CipherSuite(rawValue: rawCiperSuite)!
        self.legacyCompressionMethod = CompressionMethod(rawValue: rawCompressionMethod)!
        
        if bytesLeft > 0 {
            if let extensions = TLSReadExtensions(from: inputStream, length: bytesLeft, messageType: .serverHello) {
                self.extensions = extensions
            }
        }

        super.init(type: .handshake(.serverHello))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        var buffer = DataBuffer()
        
        buffer.write(self.legacyVersion.rawValue)
        
        random.writeTo(&buffer)
        
        if let session_id = self.legacySessionID {
            session_id.writeTo(&buffer)
        }
        else {
            buffer.write(UInt8(0))
        }
        
        buffer.write(self.cipherSuite.rawValue)
        
        buffer.write(self.legacyCompressionMethod!.rawValue)
        
        TLSWriteExtensions(&buffer, extensions: self.extensions)

        let data = buffer.buffer
        
        self.writeHeader(type: .serverHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
