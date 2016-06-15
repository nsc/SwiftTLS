//
//  TLSClientHello.swift
//
//  Created by Nico Schmidt on 15.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

enum TLSHelloExtensionType : UInt16
{
    case serverName = 0
    case ellipticCurves = 10
    case ecPointFormats = 11
}

protocol TLSHelloExtension : Streamable
{
    var extensionType : TLSHelloExtensionType {
        get
    }
}

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
    
    var extensions : [TLSHelloExtension] = []
    
    init(clientVersion : TLSProtocolVersion, random : Random, sessionID : SessionID?, cipherSuites : [CipherSuite], compressionMethods : [CompressionMethod])
    {
        self.clientVersion = clientVersion
        self.random = random
        self.sessionID = sessionID
        self.rawCipherSuites = []
        self.compressionMethods = compressionMethods
        
        super.init(type: .handshake(.clientHello))
        
        self.cipherSuites = cipherSuites
    }
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.clientHello,
            let major : UInt8? = inputStream.read(),
            let minor : UInt8? = inputStream.read(),
            let clientVersion = TLSProtocolVersion(major: major!, minor: minor!),
            let random = Random(inputStream: inputStream),
            let sessionIDSize : UInt8 = inputStream.read()
        else {
            return nil
        }
        
        let rawSessionID : [UInt8]? = sessionIDSize > 0 ? inputStream.read(count: Int(sessionIDSize)) : nil

        guard
            let rawCipherSuitesRead : [UInt16] = inputStream.read16(),
            let rawCompressionMethods : [UInt8] = inputStream.read8()
        else {
            return nil
        }
        
        var bytesLeft = bodyLength - 34
        bytesLeft -= 1 + Int(sessionIDSize)
        bytesLeft -= 2 + rawCipherSuitesRead.count * 2
        bytesLeft -= 1 + rawCompressionMethods.count

        if bytesLeft > 0 {
            guard
                let extensionsSize : UInt16 = inputStream.read(),
                let extensionsData : [UInt8] = inputStream.read(count: Int(extensionsSize))
            else {
                return nil
            }

            print("Extensions Size: \(extensionsSize)")
            print("Extensions Data:\n\(hex(extensionsData))")
            
            bytesLeft -= 2 + extensionsData.count
            
            if bytesLeft > 0 {
                print("Error: excess bytes at the end of client hello")
            }
            
            let buffer = BinaryInputStream(extensionsData)
            var extensionBytesLeft = extensionsData.count
            self.extensions = []
            repeat {
                
                if let rawExtensionType : UInt16 = buffer.read(), let extensionData : [UInt8] = buffer.read16() {
                    
                    extensionBytesLeft -= 2 + 2 + extensionData.count
                 
                    if let extensionType = TLSHelloExtensionType(rawValue: rawExtensionType) {

                        switch (extensionType)
                        {
                        case .serverName:
                            if let serverName = TLSServerNameExtension(inputStream: BinaryInputStream(extensionData)) {
                                self.extensions.append(serverName)
                            }
                            
                        case .ellipticCurves:
                            if let ellipticCurves = TLSEllipticCurvesExtension(inputStream: BinaryInputStream(extensionData)) {
                                self.extensions.append(ellipticCurves)
                            }

                        case .ecPointFormats:
                            if let pointFormats = TLSEllipticCurvePointFormatsExtension(inputStream: BinaryInputStream(extensionData)) {
                                self.extensions.append(pointFormats)
                            }

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
        }
        
        self.clientVersion = clientVersion
        self.random = random
        
        if let rawSessionID = rawSessionID {
            self.sessionID = SessionID(sessionID: rawSessionID)
        }
        
        self.rawCipherSuites = rawCipherSuitesRead
        self.compressionMethods = rawCompressionMethods.map {CompressionMethod(rawValue: $0)!}
        
        super.init(type: .handshake(.clientHello))
    }

    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
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
        
        buffer.write(UInt16(rawCipherSuites.count * sizeof(UInt16.self)))
        buffer.write( rawCipherSuites)
        
        buffer.write(UInt8(compressionMethods.count))
        buffer.write(compressionMethods.map { $0.rawValue})
        
        if self.extensions.count != 0 {
            var extensionsData = DataBuffer()
            
            for helloExtension in self.extensions {
                helloExtension.writeTo(&extensionsData)
            }

            buffer.write(UInt16(extensionsData.buffer.count))
            buffer.write(extensionsData.buffer)
        }
        
        let data = buffer.buffer
        
        self.writeHeader(type: .clientHello, bodyLength: data.count, target: &target)
        target.write(data)
    }
}
