//
//  TLSClientHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

class TLSClientHello : TLSHandshakeMessage
{
    var legacyVersion: TLSProtocolVersion
    var random: Random
    var legacySessionID: TLSSessionID?
    var rawCipherSuites: [UInt16]
    var cipherSuites: [CipherSuite] {
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
    
    var legacyCompressionMethods: [CompressionMethod]
    
    var extensions: [TLSExtension] = []
    
    init(configuration: TLSConfiguration, random: Random, sessionID: TLSSessionID?, cipherSuites: [CipherSuite], compressionMethods: [CompressionMethod] = [.null])
    {
        if configuration.supports(TLSProtocolVersion.v1_3) {
            self.legacyVersion = TLSProtocolVersion.v1_2
            let supportedVersions = TLSSupportedVersionsExtension(supportedVersions: configuration.supportedVersions)
            self.extensions.append(supportedVersions)
        }
        else {
            self.legacyVersion = configuration.supportedVersions[0]
        }
        self.random = random
        self.legacySessionID = sessionID
        self.rawCipherSuites = []
        self.legacyCompressionMethods = compressionMethods
        
        super.init(type: .handshake(.clientHello))
        
        self.cipherSuites = cipherSuites
    }
    
    required init?(inputStream: InputStreamType, context: TLSConnection)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.clientHello,
            let major: UInt8 = inputStream.read(),
            let minor: UInt8 = inputStream.read(),
            let random = Random(inputStream: inputStream),
            let sessionIDSize: UInt8 = inputStream.read()
        else {
            return nil
        }
        
        let rawSessionID: [UInt8]? = sessionIDSize > 0 ? inputStream.read(count: Int(sessionIDSize)) : nil

        guard
            let rawCipherSuitesRead: [UInt16] = inputStream.read16(),
            let rawCompressionMethods: [UInt8] = inputStream.read8()
        else {
            return nil
        }
        
        var bytesLeft = bodyLength - 34
        bytesLeft -= 1 + Int(sessionIDSize)
        bytesLeft -= 2 + rawCipherSuitesRead.count * 2
        bytesLeft -= 1 + rawCompressionMethods.count

        if bytesLeft > 0 {
            if let extensions = TLSReadExtensions(from: inputStream, length: bytesLeft, messageType: .clientHello) {
                self.extensions = extensions
            }
        }

        let clientVersion = TLSProtocolVersion(major: major, minor: minor)

        self.legacyVersion = clientVersion
        self.random = random
        
        if let rawSessionID = rawSessionID {
            self.legacySessionID = TLSSessionID(rawSessionID)
        }
        
        self.rawCipherSuites = rawCipherSuitesRead
        print("compression methods: \(rawCompressionMethods)")
        self.legacyCompressionMethods = rawCompressionMethods.compactMap {CompressionMethod(rawValue: $0)}
        print("Known compression methods: \(self.legacyCompressionMethods)")

        super.init(type: .handshake(.clientHello))
    }

    override func writeTo<Target: OutputStreamType>(_ target: inout Target)
    {
        var buffer = DataBuffer()
        
        buffer.write(legacyVersion.rawValue)
        
        random.writeTo(&buffer)
        
        if let session_id = self.legacySessionID {
            session_id.writeTo(&buffer)
        }
        else {
            buffer.write(UInt8(0))
        }
        
        buffer.write(UInt16(rawCipherSuites.count * MemoryLayout<UInt16>.size))
        buffer.write(rawCipherSuites)
        
        buffer.write(UInt8(self.legacyCompressionMethods.count))
        buffer.write(self.legacyCompressionMethods.map { $0.rawValue})
        
        TLSWriteExtensions(&buffer, extensions: self.extensions, messageType: .clientHello)
        
        let data = buffer.buffer
        
        self.writeHeader(type: .clientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
