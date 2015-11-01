//
//  TLSEllipticCurvesExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 11.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

class TLSEllipticCurvesExtension : TLSHelloExtension
{
    var extensionType : TLSHelloExtensionType {
        get {
            return .EllipticCurves
        }
    }
    
    var ellipticCurves : [NamedCurve]
    
    init(ellipticCurves : [NamedCurve])
    {
        self.ellipticCurves = ellipticCurves
    }
    
    required init?(inputStream: InputStreamType) {
        self.ellipticCurves = []
        
        guard
            let rawEllipticCurves : [UInt16] = inputStream.read16()
            else {
                return nil
        }

        for ec in rawEllipticCurves
        {
            if let ellipticCurve = NamedCurve(rawValue: ec) {
                self.ellipticCurves.append(ellipticCurve)
            }
            else {
                return nil
            }
        }
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
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