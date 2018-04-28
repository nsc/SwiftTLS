//
//  TLSServerHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public class TLSServerHello : TLSHandshakeMessage
{
    var legacyVersion : TLSProtocolVersion
    var random : Random
    var legacySessionID : TLSSessionID?
    public private(set) var cipherSuite : CipherSuite
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
    
    var isHelloRetryRequest: Bool {
        return self.random == helloRetryRequestRandom
    }
    
    init(serverVersion : TLSProtocolVersion, random : Random, sessionID : TLSSessionID? = nil, cipherSuite : CipherSuite, compressionMethod : CompressionMethod = .null)
    {
        self.legacyVersion = serverVersion
        self.random = random
        self.legacySessionID = sessionID
        self.cipherSuite = cipherSuite
        self.legacyCompressionMethod = compressionMethod
        
        super.init(type: .handshake(.serverHello))
    }
    
    required public init?(inputStream : InputStreamType, context: TLSConnection)
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
            let messageType: TLSMessageExtensionType = (self.random == helloRetryRequestRandom) ? .helloRetryRequest : .serverHello

            // In TLS 1.2 extensions are optional, i.e. they are only read if there are left-over bytes at the end of the message
            if bytesLeft > 0 {
                self.extensions = TLSReadExtensions(from: inputStream, length: bytesLeft, messageType: messageType, context: context)
            }
            else {
                self.extensions = []
            }
        }

        super.init(type: .handshake(.serverHello))
    }
    
    override public func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        var data = [UInt8]()
        
        data.write(self.legacyVersion.rawValue)
        
        random.writeTo(&data, context: context)
        
        if let session_id = self.legacySessionID {
            session_id.writeTo(&data, context: context)
        }
        else {
            data.write(UInt8(0))
        }
        
        data.write(self.cipherSuite.rawValue)
        
        data.write(self.legacyCompressionMethod!.rawValue)
        
        if self.extensions.count != 0 {
            TLSWriteExtensions(&data, extensions: self.extensions, messageType: .serverHello, context: context)
        }
        
        self.writeHeader(type: .serverHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
