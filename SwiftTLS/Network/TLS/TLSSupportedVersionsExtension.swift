//
//  TLSSupportedVersionsExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 04.11.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLSSupportedVersionsExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .supportedVersions
        }
    }

    var supportedVersions: [TLSProtocolVersion]
    
    init(supportedVersions : [TLSProtocolVersion])
    {
        self.supportedVersions = supportedVersions
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        self.supportedVersions = []
        
        switch messageType {
            
        case .clientHello:
            guard
                let rawSupportedVersions : [UInt16] = inputStream.read8()
                else {
                    return nil
            }
            
            for rawVersion in rawSupportedVersions
            {
                if let version = TLSProtocolVersion(rawValue: rawVersion) {
                    self.supportedVersions.append(version)
                }
                else {
                    return nil
                }
            }
            
        case .serverHello:
            guard
                let rawSupportedVersion: UInt16 = inputStream.read()
            else {
                    return nil
            }
            
            guard let version = TLSProtocolVersion(rawValue: rawSupportedVersion) else {
                return nil
            }
            
            self.supportedVersions.append(version)
        
        default:
            fatalError("Supported Version is not a valid extension in \(extensionType)")
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        let data = DataBuffer()
        for version in self.supportedVersions {
            data.write(version.rawValue)
        }
        
        let extensionsData = data.buffer
        let extensionsLength = extensionsData.count
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionsData.count + 1))
        target.write(UInt8(extensionsLength))
        target.write(extensionsData)
    }
   
}
