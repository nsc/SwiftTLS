//
//  TLSSupportedGroupsExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 11.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

struct TLSSupportedGroupsExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .supportedGroups
        }
    }
    
    var ellipticCurves : [NamedGroup]
    
    init(ellipticCurves : [NamedGroup])
    {
        self.ellipticCurves = ellipticCurves
    }
    
    init?(inputStream: InputStreamType) {
        self.ellipticCurves = []
        
        guard
            let rawEllipticCurves : [UInt16] = inputStream.read16()
            else {
                return nil
        }

        for ec in rawEllipticCurves
        {
            guard let ellipticCurve = NamedGroup(rawValue: ec) else {
                continue
            }
            
            self.ellipticCurves.append(ellipticCurve)
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        let data = DataBuffer()
        for ec in self.ellipticCurves {
            data.write(ec.rawValue)
        }
        
        let extensionsData = data.buffer
        let extensionsLength = extensionsData.count
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionsData.count + 2))
        target.write(UInt16(extensionsLength))
        target.write(extensionsData)
    }
}
