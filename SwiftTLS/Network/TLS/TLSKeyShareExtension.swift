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
        guard let namedGroup = NamedGroup(inputStream: inputStream) else {
            return nil
        }
        
        guard let keyExchange : [UInt8] = inputStream.read16() else {
            return nil
        }

        self.namedGroup = namedGroup
        self.keyExchange = keyExchange
    }
    
    init(namedGroup: NamedGroup, keyExchange: [UInt8])
    {
        self.namedGroup = namedGroup
        self.keyExchange = keyExchange
    }
}

extension KeyShareEntry : Streamable {
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        target.write(namedGroup)
        target.write(UInt16(keyExchange.count))
        target.write(keyExchange)
    }
}

enum KeyShare {
    case clientHello(clientShares : [KeyShareEntry])
    case helloRetryRequest(selectedGroup: NamedGroup)
    case serverHello(serverShare: KeyShareEntry)
}

enum TLSHelloType {
    case clientHello
    case helloRetryRequest
    case serverHello
}

struct TLSKeyShareExtension : TLSHelloExtension
{
    var extensionType : TLSHelloExtensionType {
        get {
            return .keyShare
        }
    }
    
    var keyShare: KeyShare
    
    init(keyShare: KeyShare)
    {
        self.keyShare = keyShare
    }
    
    init?(inputStream: InputStreamType, helloType: TLSHelloType) {
        
        switch helloType {
        case .clientHello:
            guard let numBytes16 : UInt16 = inputStream.read() else {
                return nil
            }
            
            var numBytes = Int(numBytes16)
            var clientShares: [KeyShareEntry] = []
            
            while numBytes > 0 {
                guard let keyShareEntry = KeyShareEntry(inputStream: inputStream) else {
                    return nil
                }
                
                numBytes -= 2 + keyShareEntry.keyExchange.count
                
                clientShares.append(keyShareEntry)
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
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        var data = DataBuffer()
        
        switch keyShare {
        case .clientHello(let clientShares):
            for clientShare in clientShares {
                clientShare.writeTo(&data)
            }
            
        case .helloRetryRequest(let selectedGroup):
            selectedGroup.writeTo(&data)

        case .serverHello(let serverShare):
            serverShare.writeTo(&data)
        }
        
        let extensionsData = data.buffer
        let extensionsLength = extensionsData.count
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionsData.count + 2))
        target.write(UInt16(extensionsLength))
        target.write(extensionsData)
    }
    
}
