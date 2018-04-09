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
        
        self.random = TLSRandomBytes(count: PreMasterSecret.NumberOfRandomBytes)
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
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write(self.clientVersion.rawValue)
        target.write(random)
    }
}

class TLSClientKeyExchange : TLSHandshakeMessage
{
    var encryptedPreMasterSecret : [UInt8]?
    var keyExchange : KeyExchange
    
    init(preMasterSecret : [UInt8], rsa : RSA)
    {
        self.encryptedPreMasterSecret = try! rsa.encrypt(preMasterSecret)
        self.keyExchange = .rsa
        
        super.init(type: .handshake(.clientKeyExchange))
    }
    
    init(keyExchange: KeyExchange)
    {
        self.keyExchange = keyExchange
        super.init(type: .handshake(.clientKeyExchange))
    }
    
//    init(diffieHellmanPublicKey : BigInt)
//    {
//        self.diffieHellmanPublicKey = diffieHellmanPublicKey
//        
//        super.init(type: .handshake(.clientKeyExchange))
//    }
//    
//    init(ecdhPublicKey : EllipticCurvePoint)
//    {
//        self.ecdhPublicKey = ecdhPublicKey
//        
//        super.init(type: .handshake(.clientKeyExchange))
//    }

    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard let (type, _) = TLSHandshakeMessage.readHeader(inputStream) else {
            return nil
        }
        
        // TODO: check consistency of body length and the data following
        if type == TLSHandshakeType.clientKeyExchange {

            switch context.keyExchange {
            case .ecdhe(let keyExchange as ECDHKeyExchange):
                guard let rawPublicKeyPoint : [UInt8] = inputStream.read8() else { return nil }
                guard let ecdhPublicKey = EllipticCurvePoint(data: rawPublicKeyPoint) else { return nil }
                
                keyExchange.Q = ecdhPublicKey
                self.keyExchange = .ecdhe(keyExchange)
            
            case .dhe(let keyExchange as DHKeyExchange):
                guard let data : [UInt8] = inputStream.read16() else { return nil }
                
                keyExchange.Ys = BigInt(bigEndianParts: data)
                self.keyExchange = .dhe(keyExchange)
                
            case .rsa:
                guard let data : [UInt8] = inputStream.read16() else { return nil }
                
                self.encryptedPreMasterSecret = data
                self.keyExchange = .rsa
                
            default:
                return nil
            }
            
            super.init(type: .handshake(.clientKeyExchange))
            
            return
        }
        
        return nil        
    }

    override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        switch self.keyExchange
        {
        case .dhe(let keyExchange):
            if let publicKey = keyExchange.publicKey {
                self.writeHeader(type: .clientKeyExchange, bodyLength: publicKey.count + 2, target: &target)
                target.write16(publicKey)
            }
            
        case .ecdhe(let keyExchange):
            if let publicKey = keyExchange.publicKey {
                self.writeHeader(type: .clientKeyExchange, bodyLength: publicKey.count + 1, target: &target)
                target.write8(publicKey)
            }
        
        case .rsa:
            if let encryptedPreMasterSecret = self.encryptedPreMasterSecret {
                self.writeHeader(type: .clientKeyExchange, bodyLength: encryptedPreMasterSecret.count + 2, target: &target)
                target.write16(encryptedPreMasterSecret)
            }
        }

    }
}
