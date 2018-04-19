//
//  TLSEarlyDataIndication.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 07.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLSEarlyDataIndication : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .earlyData
        }
    }

    var maxEarlyDataSize: UInt32?
    init(maxEarlyDataSize: UInt32? = nil)
    {
        self.maxEarlyDataSize = maxEarlyDataSize
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        
        switch messageType {
        case .newSessionTicket:
            guard let size: UInt32 = inputStream.read() else {
                return nil
            }
            
            self.maxEarlyDataSize = size
            
        case .clientHello, .encryptedExtensions:
            break
            
        default:
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {

        let extensionData: [UInt8]
        switch messageType {
        case .clientHello, .encryptedExtensions:
            extensionData = []
        case .newSessionTicket:
            guard let maxEarlyDataSize = self.maxEarlyDataSize else {
                fatalError("EarlyDataIndication extension in NewSessionTicket is missing maxEarlyDataSize")
            }
            
            extensionData = UInt32(maxEarlyDataSize).bigEndianBytes
        
        default:
            fatalError("EarlyDataIndication is not allowed in \(messageType)")
        }
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionData.count))
        target.write(extensionData)
    }
}
