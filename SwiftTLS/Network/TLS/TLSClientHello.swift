//
//  TLSClientHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

enum TLSHelloExtensionType : UInt16
{
    case serverName = 0
    case supportedGroups = 10
    case ecPointFormats = 11
    case signatureAlgorithms = 13
    case keyShare = 40
    case preSharedKey = 41
    case earlyData = 42
    case supportedVersions = 43
    case cookie = 44
    case secureRenegotiationInfo = 0xff01
}

protocol TLSHelloExtension : Streamable
{
    var extensionType : TLSHelloExtensionType {
        get
    }
    
}

func TLSReadHelloExtensions(from inputStream: InputStreamType, length: Int) -> [TLSHelloExtension]?
{
    guard
        let extensionsSize : UInt16 = inputStream.read(),
        let extensionsData : [UInt8] = inputStream.read(count: Int(extensionsSize))
        else {
            return nil
    }
    
    var length = length
    length -= 2 + extensionsData.count
    
    if length > 0 {
        print("Error: excess bytes at the end of client hello")
    }
    
    let buffer = BinaryInputStream(extensionsData)
    var extensionBytesLeft = extensionsData.count
    var extensions: [TLSHelloExtension] = []
    repeat {
        
        if let rawExtensionType : UInt16 = buffer.read(), let extensionData : [UInt8] = buffer.read16() {
            
            extensionBytesLeft -= 2 + 2 + extensionData.count
            
            if let extensionType = TLSHelloExtensionType(rawValue: rawExtensionType) {
                
                switch (extensionType)
                {
                case .serverName:
                    if let serverName = TLSServerNameExtension(inputStream: BinaryInputStream(extensionData)) {
                        extensions.append(serverName)
                    }
                    
                case .supportedGroups:
                    if let ellipticCurves = TLSSupportedGroupsExtension(inputStream: BinaryInputStream(extensionData)) {
                        extensions.append(ellipticCurves)
                    }
                    
                case .ecPointFormats:
                    if let pointFormats = TLSEllipticCurvePointFormatsExtension(inputStream: BinaryInputStream(extensionData)) {
                        extensions.append(pointFormats)
                    }
                    
                case .supportedVersions:
                    if let supportedVersions = TLSSupportedVersionsExtension(inputStream: BinaryInputStream(extensionData)) {
                        extensions.append(supportedVersions)
                    }
                    
                case .secureRenegotiationInfo:
                    if let secureRenogotiationInfo = TLSSecureRenegotiationInfoExtension(inputStream: BinaryInputStream(extensionData)) {
                        extensions.append(secureRenogotiationInfo)
                    }
                    
                default:
                    print("Unsupported extension type \(rawExtensionType)")
                    
                }
            }
            else {
                print("Unknown extension type \(rawExtensionType)")
            }
            
            if extensionBytesLeft == 0 {
                break
            }
        }
    } while(true)
    
    return extensions
}

func TLSWriteHelloExtensions<Target: OutputStreamType>(_ target: inout Target, extensions: [TLSHelloExtension])
{
    if extensions.count != 0 {
        var extensionsData = DataBuffer()
        
        for helloExtension in extensions {
            helloExtension.writeTo(&extensionsData)
        }
        
        target.write(UInt16(extensionsData.buffer.count))
        target.write(extensionsData.buffer)
    }
}

class TLSClientHello : TLSHandshakeMessage
{
    var legacyVersion : TLSProtocolVersion
    var random : Random
    var legacySessionID : TLSSessionID?
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
    
    var legacyCompressionMethods : [CompressionMethod]
    
    var extensions : [TLSHelloExtension] = []
    
    init(configuration: TLSConfiguration, random: Random, sessionID: TLSSessionID?, cipherSuites: [CipherSuite], compressionMethods: [CompressionMethod] = [.null])
    {
        if configuration.supports(version: TLSProtocolVersion.v1_3) {
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
    
    required init?(inputStream: InputStreamType, context: TLSContext)
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
            if let extensions = TLSReadHelloExtensions(from: inputStream, length: bytesLeft) {
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
        self.legacyCompressionMethods = rawCompressionMethods.flatMap {CompressionMethod(rawValue: $0)}
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
        
        TLSWriteHelloExtensions(&buffer, extensions: self.extensions)
        
        let data = buffer.buffer
        
        self.writeHeader(type: .clientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
