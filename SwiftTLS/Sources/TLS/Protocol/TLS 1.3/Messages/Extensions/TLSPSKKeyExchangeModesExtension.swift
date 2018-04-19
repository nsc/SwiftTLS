//
//  TLSPSKKeyExchangeModesExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 26.03.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

enum PSKKeyExchangeMode : UInt8
{
    case psk = 0
    case psk_dhe = 1
}

struct TLSPSKKeyExchangeModesExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .pskKeyExchangeModes
        }
    }
    
    var keyExchangeModes: [PSKKeyExchangeMode]
    
    init(keyExchangeModes: [PSKKeyExchangeMode])
    {
        self.keyExchangeModes = keyExchangeModes
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        
        switch messageType {
        case .clientHello:
            guard let numBytes8 : UInt8 = inputStream.read() else {
                return nil
            }
            
            var numBytes = Int(numBytes8)
            var keyExchangeModes: [PSKKeyExchangeMode] = []
            
            while numBytes > 0 {
                let bytesRead = inputStream.bytesRead
                
                guard
                    let rawKeyExchangeMode: UInt8 = inputStream.read(),
                    let keyExchangeMode = PSKKeyExchangeMode(rawValue: rawKeyExchangeMode)
                else {
                    return nil
                }
                
                numBytes -= (inputStream.bytesRead - bytesRead)
                
                keyExchangeModes.append(keyExchangeMode)
            }
            
            self.keyExchangeModes = keyExchangeModes

        default:
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {

        guard messageType == .clientHello else {
            fatalError("PSKKeyExchangeModes extension is only supported in ClientHello")
        }

        let rawKeyExchangeModes = self.keyExchangeModes.map({$0.rawValue})
        
        let extensionData = rawKeyExchangeModes
            
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionData.count + 1))
        target.write8(extensionData)
    }
}
