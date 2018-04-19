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
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
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
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {
        var extensionData: [UInt8] = []
        for ec in self.ellipticCurves {
            extensionData.write(ec.rawValue)
        }
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionData.count + 2))
        target.write16(extensionData)
    }
}
