//
//  TLSSecureRenegotiationInfoExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 23/08/2016.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLSSecureRenegotiationInfoExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .secureRenegotiationInfo
        }
    }
    
    var renegotiatedConnection: [UInt8]

    init(renegotiatedConnection: [UInt8] = [])
    {
        self.renegotiatedConnection = renegotiatedConnection
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        guard
            let info: [UInt8] = inputStream.read8()
            else {
                return nil
        }
        
        self.renegotiatedConnection = info
    }

    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {
        let extensionsLength = renegotiatedConnection.count + 1
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionsLength))
        target.write8(renegotiatedConnection)
    }

}
