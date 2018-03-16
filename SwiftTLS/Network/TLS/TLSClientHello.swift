//
//  TLSClientHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

enum TLSExtensionType : UInt16
{
    case serverName = 0
    case statusRequest = 5
    case supportedGroups = 10
    case ecPointFormats = 11        // TLS 1.2 only, not in TLS 1.3
    case signatureAlgorithms = 13
    case applicationLayerProtocolNegotiation = 16
    case signedCertificateTimestamp = 18
    case preSharedKey = 41
    case earlyData = 42
    case supportedVersions = 43
    case cookie = 44
    case pskKeyExchangeModes = 45
    case certificateAuthorities = 47
    case oidFilters = 48
    case postHandshakeAuth = 49
    case signatureAlgorithmsCert = 50
    case keyShare = 51

    case secureRenegotiationInfo = 0xff01
}

protocol TLSExtension : Streamable
{
    var extensionType : TLSExtensionType {
        get
    }
    
}

func TLSReadExtensions(from inputStream: InputStreamType, length: Int, messageType: TLSMessageExtensionType) -> [TLSExtension]?
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
        print("Error: excess bytes at the end of \(messageType)")
    }
    
    let buffer = BinaryInputStream(extensionsData)
    var extensionBytesLeft = extensionsData.count
    var extensions: [TLSExtension] = []
    
    while extensionBytesLeft > 0 {
        
        if let rawExtensionType : UInt16 = buffer.read(), let extensionData : [UInt8] = buffer.read16() {
            
            extensionBytesLeft -= 2 + 2 + extensionData.count
            
            if let extensionType = TLSExtensionType(rawValue: rawExtensionType) {
                
                switch (extensionType)
                {
                case .serverName:
                    if extensionData.count == 0 {
                        extensions.append(TLSServerNameExtension(serverNames: []))
                        break
                    }
                    
                    guard let serverName = TLSServerNameExtension(inputStream: BinaryInputStream(extensionData)) else {
                        fatalError("Could not read server name extension")
                    }
                    
                    extensions.append(serverName)
                    
                case .supportedGroups:
                    guard let ellipticCurves = TLSSupportedGroupsExtension(inputStream: BinaryInputStream(extensionData)) else {
                    
                        fatalError("Could not read supported groups extension")
                    }

                    extensions.append(ellipticCurves)
                    
                case .ecPointFormats:
                    guard let pointFormats = TLSEllipticCurvePointFormatsExtension(inputStream: BinaryInputStream(extensionData)) else {
                    
                        fatalError("Could not read EC point formats extension")
                    }
                    
                    extensions.append(pointFormats)
                    
                case .keyShare:
                    guard let keyShare = TLSKeyShareExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {

                        fatalError("Could not read key share extension")
                    }
                    
                    extensions.append(keyShare)
                    
                case .supportedVersions:
                    guard let supportedVersions = TLSSupportedVersionsExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                        fatalError("Could not read supported versions extension")
                    }
                    
                    extensions.append(supportedVersions)
                    
                case .secureRenegotiationInfo:
                    guard let secureRenogotiationInfo = TLSSecureRenegotiationInfoExtension(inputStream: BinaryInputStream(extensionData)) else {
                    
                        fatalError("Could not read secure renegotiation info extension")
                    }
                    
                    extensions.append(secureRenogotiationInfo)
                    
                case .signatureAlgorithms:
                    break
                    
                default:
                    print("Unsupported extension type \(rawExtensionType)")
                    
                }
            }
            else {
                print("Unknown extension type \(rawExtensionType)")
            }
        }
    }
    
    return extensions
}

func TLSWriteExtensions<Target: OutputStreamType>(_ target: inout Target, extensions: [TLSExtension])
{
    if extensions.count != 0 {
        var extensionsData = DataBuffer()
        
        for anExtension in extensions {
            anExtension.writeTo(&extensionsData)
        }
        
        target.write(UInt16(extensionsData.buffer.count))
        target.write(extensionsData.buffer)
    }
}

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
        
        TLSWriteExtensions(&buffer, extensions: self.extensions)
        
        let data = buffer.buffer
        
        self.writeHeader(type: .clientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
