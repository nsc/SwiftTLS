//
//  TLSKeyShareExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

struct KeyShareEntry {
    var namedGroup: NamedGroup
    var keyExchange: [UInt8]
    
    init?(inputStream: InputStreamType)
    {
        // When we don't know the named group, we still have to read the whole
        // entry. Therefore the check if namedGroup is nil is done further below.
        let namedGroup = NamedGroup(inputStream: inputStream)
        guard let keyExchange : [UInt8] = inputStream.read16() else {
            return nil
        }
        
        guard let group = namedGroup else {
            return nil
        }

        self.namedGroup = group
        self.keyExchange = keyExchange
    }
    
    init(namedGroup: NamedGroup, keyExchange: [UInt8])
    {
        self.namedGroup = namedGroup
        self.keyExchange = keyExchange
    }
}

extension KeyShareEntry : Streamable {
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write(namedGroup)
        target.write16(keyExchange)
    }
}

enum KeyShare {
    case clientHello(clientShares : [KeyShareEntry])
    case helloRetryRequest(selectedGroup: NamedGroup)
    case serverHello(serverShare: KeyShareEntry)
}

enum TLSMessageExtensionType {
    case clientHello
    case helloRetryRequest
    case serverHello
    case encryptedExtensions
    case certificate
    case certificateRequest
    case newSessionTicket
}

struct TLSKeyShareExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .keyShare
        }
    }
    
    var keyShare: KeyShare
    
    init(keyShare: KeyShare)
    {
        self.keyShare = keyShare
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        
        switch messageType {
        case .clientHello:
            guard let numBytes16 : UInt16 = inputStream.read() else {
                return nil
            }
            
            var numBytes = Int(numBytes16)
            var clientShares: [KeyShareEntry] = []
            
            while numBytes > 0 {
                let bytesRead = inputStream.bytesRead
                let keyShareEntry = KeyShareEntry(inputStream: inputStream)
                
                numBytes -= (inputStream.bytesRead - bytesRead)

                if let keyShareEntry = keyShareEntry {
                    clientShares.append(keyShareEntry)
                }
            }
            
            self.keyShare = .clientHello(clientShares: clientShares)
            
        case .helloRetryRequest:
            guard let selectedGroup = NamedGroup(inputStream: inputStream) else {
                return nil
            }
            
            self.keyShare = .helloRetryRequest(selectedGroup: selectedGroup)
            
        case .serverHello:
            guard let keyShareEntry = KeyShareEntry(inputStream: inputStream) else {
                return nil
            }
            
            self.keyShare = .serverHello(serverShare: keyShareEntry)
        
        default:
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {
        var extensionData: [UInt8] = []
        
        switch keyShare {
        case .clientHello(let clientShares):
            for clientShare in clientShares {
                clientShare.writeTo(&extensionData, context: context)
            }
            
            target.write(self.extensionType.rawValue)
            target.write(UInt16(extensionData.count + 2))
            target.write16(extensionData)
            
        case .helloRetryRequest(let selectedGroup):
            selectedGroup.writeTo(&extensionData, context: context)
            
            target.write(self.extensionType.rawValue)
            target.write16(extensionData)

        case .serverHello(let serverShare):
            serverShare.writeTo(&extensionData, context: context)
            
            target.write(self.extensionType.rawValue)
            target.write16(extensionData)
        }
        
    }
    
}
