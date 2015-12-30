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
        if  let major : UInt8 = inputStream.read(),
            let minor : UInt8 = inputStream.read(),
            let bytes : [UInt8] = inputStream.read(count: Random.NumberOfRandomBytes)
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
        target.write(self.clientVersion.rawValue)
        target.write(random)
    }
}

class TLSClientKeyExchange : TLSHandshakeMessage
{
    var encryptedPreMasterSecret : [UInt8]?
    var diffieHellmanPublicKey : BigInt?
    var ecdhPublicKey : EllipticCurvePoint?
    
    init(preMasterSecret : [UInt8], publicKey : CryptoKey)
    {
        if let crypttext = publicKey.encrypt(preMasterSecret) {
            self.encryptedPreMasterSecret = crypttext
        }
        else {
            self.encryptedPreMasterSecret = []
            assert(false)
        }
        
        super.init(type: .Handshake(.ClientKeyExchange))
    }
    
    init(diffieHellmanPublicKey : BigInt)
    {
        self.diffieHellmanPublicKey = diffieHellmanPublicKey
        
        super.init(type: .Handshake(.ClientKeyExchange))
    }
    
    init(ecdhPublicKey : EllipticCurvePoint)
    {
        self.ecdhPublicKey = ecdhPublicKey
        
        super.init(type: .Handshake(.ClientKeyExchange))
    }

    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard let (type, _) = TLSHandshakeMessage.readHeader(inputStream) else {
            super.init(type: .Handshake(.ClientKeyExchange))

            return nil
        }
        
        // TODO: check consistency of body length and the data following
        if type == TLSHandshakeType.ClientKeyExchange {
            if let length : UInt16 = inputStream.read() {
                if let data : [UInt8] = inputStream.read(count: Int(length)) {
                    
                    if context.dhKeyExchange != nil {
                        self.diffieHellmanPublicKey = BigInt(bigEndianParts: data)
                    }
                    else if context.ecdhKeyExchange != nil {
                        // FIXME: Implement client key exchange on server side
                        precondition(false)
                    }
                    else {
                        self.encryptedPreMasterSecret = data
                    }
                    
                    super.init(type: .Handshake(.ClientKeyExchange))
                    
                    return
                }
            }
        }

        self.encryptedPreMasterSecret = []
        super.init(type: .Handshake(.ClientKeyExchange))
        
        return nil        
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        if let encryptedPreMasterSecret = self.encryptedPreMasterSecret {
            self.writeHeader(type: .ClientKeyExchange, bodyLength: encryptedPreMasterSecret.count + 2, target: &target)
            target.write(UInt16(encryptedPreMasterSecret.count))
            target.write(encryptedPreMasterSecret)
        }
        else if let diffieHellmanPublicKey = self.diffieHellmanPublicKey {
            let diffieHellmanPublicKeyData = diffieHellmanPublicKey.asBigEndianData()

            self.writeHeader(type: .ClientKeyExchange, bodyLength: diffieHellmanPublicKeyData.count + 2, target: &target)
            target.write(UInt16(diffieHellmanPublicKeyData.count))
            target.write(diffieHellmanPublicKeyData)
        }
        else if let ecdhPublicKey = self.ecdhPublicKey {
            let Q = ecdhPublicKey
            let data = Q.x.asBigEndianData() + Q.y.asBigEndianData()
            
            self.writeHeader(type: .ClientKeyExchange, bodyLength: data.count + 2, target: &target)
            target.write(UInt8(data.count + 1))
            target.write(UInt8(4)) // uncompressed ECPoint encoding
            target.write(data)
        }

    }
}
