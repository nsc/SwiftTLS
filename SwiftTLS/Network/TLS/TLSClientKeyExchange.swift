//
//  TLSClientKeyExchange.swift
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
        
        self.random = [UInt8](repeating: 0, count: PreMasterSecret.NumberOfRandomBytes)
        
        arc4random_buf(&self.random, PreMasterSecret.NumberOfRandomBytes)
    }
    
    var clientVersion : TLSProtocolVersion
    var random : [UInt8] // 46 bytes
    
    required init?(inputStream : InputStreamType)
    {
        if  let major : UInt8 = inputStream.read(),
            let minor : UInt8 = inputStream.read(),
            let bytes : [UInt8] = inputStream.read(count: Random.NumberOfRandomBytes)
        {
            self.clientVersion = TLSProtocolVersion(major: major, minor: minor)
            self.random = bytes
        }

        return nil
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        target.write(self.clientVersion.rawValue)
        target.write(random)
    }
}

class TLSClientKeyExchange : TLSHandshakeMessage
{
    var encryptedPreMasterSecret : [UInt8]?
    var diffieHellmanPublicKey : BigInt?
    var ecdhPublicKey : EllipticCurvePoint?
    
    init(preMasterSecret : [UInt8], rsa : RSA)
    {
        self.encryptedPreMasterSecret = rsa.encrypt(preMasterSecret)
        
        super.init(type: .handshake(.clientKeyExchange))
    }
    
    init(diffieHellmanPublicKey : BigInt)
    {
        self.diffieHellmanPublicKey = diffieHellmanPublicKey
        
        super.init(type: .handshake(.clientKeyExchange))
    }
    
    init(ecdhPublicKey : EllipticCurvePoint)
    {
        self.ecdhPublicKey = ecdhPublicKey
        
        super.init(type: .handshake(.clientKeyExchange))
    }

    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard let (type, _) = TLSHandshakeMessage.readHeader(inputStream) else {
            return nil
        }
        
        // TODO: check consistency of body length and the data following
        if type == TLSHandshakeType.clientKeyExchange {

            switch context.keyExchange {
            case .ecdhe:
                if let rawPublicKeyPoint : [UInt8] = inputStream.read8() {
                    guard let ecdhPublicKey = EllipticCurvePoint(data: rawPublicKeyPoint) else { return nil }
                    self.ecdhPublicKey = ecdhPublicKey
                }
            
            case .dhe:
                if let data : [UInt8] = inputStream.read16() {
                    self.diffieHellmanPublicKey = BigInt(bigEndianParts: data)
                }
                    
            case .rsa:
                if let data : [UInt8] = inputStream.read16() {
                        self.encryptedPreMasterSecret = data
                }
            }
            
            super.init(type: .handshake(.clientKeyExchange))
            
            return
        }
        
        return nil        
    }

    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        if let encryptedPreMasterSecret = self.encryptedPreMasterSecret {
            self.writeHeader(type: .clientKeyExchange, bodyLength: encryptedPreMasterSecret.count + 2, target: &target)
            target.write(UInt16(encryptedPreMasterSecret.count))
            target.write(encryptedPreMasterSecret)
        }
        else if let diffieHellmanPublicKey = self.diffieHellmanPublicKey {
            let diffieHellmanPublicKeyData = diffieHellmanPublicKey.asBigEndianData()

            self.writeHeader(type: .clientKeyExchange, bodyLength: diffieHellmanPublicKeyData.count + 2, target: &target)
            target.write(UInt16(diffieHellmanPublicKeyData.count))
            target.write(diffieHellmanPublicKeyData)
        }
        else if let ecdhPublicKey = self.ecdhPublicKey {
            var buffer = DataBuffer()
            ecdhPublicKey.writeTo(&buffer)
            
            self.writeHeader(type: .clientKeyExchange, bodyLength: buffer.buffer.count + 2, target: &target)
            target.write(UInt8(buffer.buffer.count + 1))
            target.write(buffer.buffer)
        }

    }
}
