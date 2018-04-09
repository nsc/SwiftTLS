//
//  TLSEllipticCurvePointFormatsExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 11.10.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

struct TLSEllipticCurvePointFormatsExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .ecPointFormats
        }
    }
    
    var ellipticCurvePointFormats : [ECPointFormat]
    
    init(ellipticCurvePointFormats : [ECPointFormat])
    {
        self.ellipticCurvePointFormats = ellipticCurvePointFormats
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        self.ellipticCurvePointFormats = []
        
        guard
            let rawPointFormats : [UInt8] = inputStream.read8()
            else {
                return nil
        }
        
        for rawPointFormat in rawPointFormats
        {
            if let pointFormat = ECPointFormat(rawValue: rawPointFormat) {
                self.ellipticCurvePointFormats.append(pointFormat)
            }
            else {
                return nil
            }
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {
        var extensionData: [UInt8] = []
        for ec in self.ellipticCurvePointFormats {
            extensionData.write(ec.rawValue)
        }
                
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionData.count + 1))
        target.write8(extensionData)
    }
}
