//
//  TLSPreSharedKeyExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 26.03.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

struct PSKIdentity
{
    let identity: [UInt8]
    let obfuscatedTicketAge: UInt32
    
    init?(inputStream: InputStreamType)
    {
        guard
            let identity: [UInt8] = inputStream.read16(),
            let obfuscatedTicketAge: UInt32 = inputStream.read()
        else {
            return nil
        }
        
        self.identity = identity
        self.obfuscatedTicketAge = obfuscatedTicketAge
    }
    
    init(identity: [UInt8], obfuscatedTicketAge: UInt32)
    {
        self.identity = identity
        self.obfuscatedTicketAge = obfuscatedTicketAge
    }
}

extension PSKIdentity : Streamable {
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write16(identity)
        target.write(obfuscatedTicketAge)
    }
}

struct PSKBinderEntry
{
    let binder: [UInt8]
    
    init?(inputStream: InputStreamType)
    {
        guard let binder: [UInt8] = inputStream.read8() else {
            return nil
        }
        
        self.binder = binder
    }
    
    init(binder: [UInt8])
    {
        self.binder = binder
    }
}

extension PSKBinderEntry : Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write8(self.binder)
    }
}

struct OfferedPSKs
{
    let identities: [PSKIdentity]
    let binders: [PSKBinderEntry]
    
    init(identities: [PSKIdentity], binders: [PSKBinderEntry])
    {
        self.identities = identities
        self.binders = binders
    }
    
    var bindersNetworkSize: Int {
        return self.binders.reduce(2, {$0 + 1 + $1.binder.count})
    }
    
    init?(inputStream: InputStreamType)
    {
        guard let numBytesIdentities16 : UInt16 = inputStream.read() else {
            return nil
        }
        
        var identities: [PSKIdentity] = []
        var binders: [PSKBinderEntry] = []
        
        var numBytesIdentities = Int(numBytesIdentities16)
        
        while numBytesIdentities > 0 {
            let bytesRead = inputStream.bytesRead
            
            guard let identity = PSKIdentity(inputStream: inputStream) else {
                return nil
            }
            
            numBytesIdentities -= (inputStream.bytesRead - bytesRead)
            identities.append(identity)
        }
        
        guard let numBytesBinders16 : UInt16 = inputStream.read() else {
            return nil
        }
        
        var numBytesBinders = Int(numBytesBinders16)

        while numBytesBinders > 0 {
            let bytesRead = inputStream.bytesRead
            
            guard let binder = PSKBinderEntry(inputStream: inputStream) else {
                return nil
            }
            
            numBytesBinders -= (inputStream.bytesRead - bytesRead)
            binders.append(binder)
        }

        self.identities = identities
        self.binders = binders
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        var identitiesData: [UInt8] = []
        for identity in identities {
            identity.writeTo(&identitiesData, context: context)
        }
        
        target.write16(identitiesData)
        
        var bindersData: [UInt8] = []
        for binder in binders {
            binder.writeTo(&bindersData, context: context)
        }
        
        target.write16(bindersData)
    }
}

typealias SelectedIdentity = UInt16

enum PreSharedKey
{
    case clientHello(OfferedPSKs)
    case serverHello(SelectedIdentity)
}

struct TLSPreSharedKeyExtension : TLSExtension
{
    var extensionType : TLSExtensionType {
        get {
            return .preSharedKey
        }
    }
    
    let preSharedKey: PreSharedKey
    
    init(preSharedKey: PreSharedKey)
    {
        self.preSharedKey = preSharedKey
    }
    
    init?(inputStream: InputStreamType, messageType: TLSMessageExtensionType) {
        
        switch messageType {
        case .clientHello:
            guard let offeredPSKs = OfferedPSKs(inputStream: inputStream) else {
                return nil
            }
            
            self.preSharedKey = .clientHello(offeredPSKs)
            
        case .serverHello:
            guard let selectedIdentity: UInt16 = inputStream.read() else {
                return nil
            }

            self.preSharedKey = .serverHello(selectedIdentity)
            
        default:
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, messageType: TLSMessageExtensionType, context: TLSConnection?) {
        
        guard messageType == .clientHello || messageType == .serverHello else {
            fatalError("PreSharedKey extension is only supported in ClientHello or ServerHello")
        }
        
        switch self.preSharedKey
        {
        case .clientHello(let offeredPSKs):
            var extensionData: [UInt8] = []
            offeredPSKs.writeTo(&extensionData, context: context)
            
            target.write(self.extensionType.rawValue)
            target.write16(extensionData)

        case .serverHello(let selectedIdentity):
            target.write(self.extensionType.rawValue)
            target.write(UInt16(2))
            target.write(selectedIdentity)
        }
    }
}
