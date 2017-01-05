//
//  TLSSupportedVersionsExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 04.11.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLSSupportedVersionsExtension : TLSHelloExtension
{
    var extensionType : TLSHelloExtensionType {
        get {
            return .supportedVersions
        }
    }

    var supportedVersions: [TLSProtocolVersion]
    
    init(supportedVersions : [TLSProtocolVersion])
    {
        self.supportedVersions = supportedVersions
    }
    
    init?(inputStream: InputStreamType) {
        self.supportedVersions = []
        
        guard
            let rawSupportedVersions : [UInt16] = inputStream.read16()
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
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        let data = DataBuffer()
        for version in self.supportedVersions {
            data.write(version.rawValue)
        }
        
        let extensionsData = data.buffer
        let extensionsLength = extensionsData.count
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionsData.count + 2))
        target.write(UInt16(extensionsLength))
        target.write(extensionsData)
    }
   
}
