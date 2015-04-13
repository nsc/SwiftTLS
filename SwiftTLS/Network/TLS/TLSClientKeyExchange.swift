//
//  TLSClientKeyExchange.swift
//  Chat
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class PreMasterSecret : Streamable
{
    static let NumberOfRandomBytes = 46
    
    init(clientVersion : TLSProtocolVersion)
    {
        self.clientVersion = clientVersion
        
        self.random = [UInt8](count: PreMasterSecret.NumberOfRandomBytes, repeatedValue: 0)
        
        arc4random_buf(&self.random, PreMasterSecret.NumberOfRandomBytes)
    }
    
    var clientVersion : TLSProtocolVersion
    var random : [UInt8] // 46 bytes
    
    required init?(inputStream : InputStreamType)
    {
        if  let major : UInt8 = read(inputStream),
            let minor : UInt8 = read(inputStream),
            let bytes : [UInt8] = read(inputStream, Random.NumberOfRandomBytes)
        {
            if let version = TLSProtocolVersion(major: major, minor: minor) {
                self.clientVersion = version
                self.random = bytes
                
                return
            }
        }

        self.clientVersion = .TLS_v1_0
        self.random = []
        
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        write(target, self.clientVersion.rawValue)
        write(target, random)
    }
}

class TLSClientKeyExchange : TLSHandshakeMessage
{
    var encryptedPreMasterSecret : [UInt8]
    init(preMasterSecret : PreMasterSecret, publicKey : CryptoKey)
    {
        var dataBuffer = DataBuffer()
        preMasterSecret.writeTo(&dataBuffer)
        if let crypttext = publicKey.encrypt(dataBuffer.buffer) {
            self.encryptedPreMasterSecret = crypttext
        }
        else {
            self.encryptedPreMasterSecret = []
            assert(false)
        }
        
        super.init(type: .Handshake(.ClientKeyExchange))
    }
    
    required init?(inputStream : InputStreamType)
    {
        let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream)
        
        // TODO: check consistency of body length and the data following
        if let t = type {
            if t == TLSHandshakeType.ClientKeyExchange {
                if let length : UInt16 = read(inputStream) {
                    if let data : [UInt8] = read(inputStream, Int(length)) {
                        self.encryptedPreMasterSecret = data
                        super.init(type: .Handshake(.ClientKeyExchange))
                        
                        return
                    }
                }
            }
        }

        self.encryptedPreMasterSecret = []
        super.init(type: .Handshake(.ClientKeyExchange))
        
        return nil        
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        self.writeHeader(type: .ClientKeyExchange, bodyLength: self.encryptedPreMasterSecret.count + 2, target: &target)
        write(target, UInt16(self.encryptedPreMasterSecret.count))
        write(target, self.encryptedPreMasterSecret)
    }
}
