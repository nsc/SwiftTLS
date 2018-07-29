//
//  TLSExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 23.03.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
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

protocol TLSExtension
{
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType)
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?)
    
    var extensionType : TLSExtensionType {
        get
    }
    
}

func TLSReadExtensions(from inputStream: InputStreamType, length: Int, messageType: TLSMessageExtensionType, context: TLSConnection?) -> [TLSExtension]
{
    guard
        let extensionsSize : UInt16 = inputStream.read(),
        let extensionsData : [UInt8] = inputStream.read(count: Int(extensionsSize))
        else {
            fatalError("Could not read extensions")
    }
    
    var length = length
    length -= 2 + extensionsData.count
    
    if length > 0 {
        log("Error: excess bytes at the end of \(messageType)")
    }
    
    let buffer = BinaryInputStream(extensionsData)
    var extensionBytesLeft = extensionsData.count
    var extensions: [TLSExtension] = []
    
    while extensionBytesLeft > 0 {
        
        guard let rawExtensionType : UInt16 = buffer.read(), let extensionData : [UInt8] = buffer.read16() else {
            break
        }
        
        extensionBytesLeft -= 2 + 2 + extensionData.count
        
        if let extensionType = TLSExtensionType(rawValue: rawExtensionType) {
            
            switch (extensionType)
            {
            case .serverName:
                if extensionData.count == 0 {
                    extensions.append(TLSServerNameExtension(serverNames: []))
                    break
                }
                
                guard let serverName = TLSServerNameExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    fatalError("Could not read server name extension")
                }
                
                extensions.append(serverName)
                
            case .supportedGroups:
                guard let ellipticCurves = TLSSupportedGroupsExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read supported groups extension")
                }
                
                extensions.append(ellipticCurves)
                
            case .ecPointFormats:
                guard let pointFormats = TLSEllipticCurvePointFormatsExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read EC point formats extension")
                }
                
                extensions.append(pointFormats)
                
            case .keyShare:
                guard let keyShare = TLSKeyShareExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read key share extension")
                }
                
                extensions.append(keyShare)
                
            case .preSharedKey:
                guard let preSharedKey = TLSPreSharedKeyExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read pre shared key extension")
                }
                
                extensions.append(preSharedKey)
                
            case .earlyData:
                guard let earlyData = TLSEarlyDataIndication(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read early data extension")
                }
                
                extensions.append(earlyData)
                
            case .pskKeyExchangeModes:
                guard let pskKeyExchangeModes = TLSPSKKeyExchangeModesExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read PSK key exchange modes extension")
                }
                
                extensions.append(pskKeyExchangeModes)
                
            case .supportedVersions:
                guard let supportedVersions = TLSSupportedVersionsExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read supported versions extension")
                }
                
                extensions.append(supportedVersions)
                
            case .secureRenegotiationInfo:
                guard let secureRenogotiationInfo = TLSSecureRenegotiationInfoExtension(inputStream: BinaryInputStream(extensionData), messageType: messageType) else {
                    
                    fatalError("Could not read secure renegotiation info extension")
                }
                
                extensions.append(secureRenogotiationInfo)
                
            case .signatureAlgorithms:
                break
                
            default:
                log("Unsupported extension type \(rawExtensionType)")
                
            }
        }
        else {
            log("Unknown extension type \(rawExtensionType)")
        }
    }
    
    return extensions
}

func TLSWriteExtensions<Target: OutputStreamType>(_ target: inout Target, extensions: [TLSExtension], messageType: TLSMessageExtensionType, context: TLSConnection?)
{
    var extensionData = [UInt8]()
    for anExtension in extensions {
        anExtension.writeTo(&extensionData, messageType: messageType, context: context)
    }
    
    target.write16(extensionData)
}
