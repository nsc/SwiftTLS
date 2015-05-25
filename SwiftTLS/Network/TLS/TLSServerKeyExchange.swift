//
//  TLSServerKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServerKeyExchange : TLSHandshakeMessage
{
    var encryptedPreMasterSecret : [UInt8]
    init(preMasterSecret : [UInt8], publicKey : CryptoKey)
    {
        if let crypttext = publicKey.encrypt(preMasterSecret) {
            self.encryptedPreMasterSecret = crypttext
            var data = crypttext
            NSData(bytesNoCopy: &data, length: data.count, freeWhenDone: false).writeToFile("/Users/nico/tmp/preMasterSecret", atomically: true)
        }
        else {
            self.encryptedPreMasterSecret = []
            assert(false)
        }
        
        super.init(type: .Handshake(.ServerKeyExchange))
    }
    
    required init?(inputStream : InputStreamType)
    {
        let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream)
        
        // TODO: check consistency of body length and the data following
        if let t = type {
            if t == TLSHandshakeType.ServerKeyExchange {
                if let length : UInt16 = read(inputStream) {
                    if let data : [UInt8] = read(inputStream, Int(length)) {
                        self.encryptedPreMasterSecret = data
                        super.init(type: .Handshake(.ServerKeyExchange))
                        
                        return
                    }
                }
            }
        }
        
        self.encryptedPreMasterSecret = []
        super.init(type: .Handshake(.ServerKeyExchange))
        
        return nil
    }
    
    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        self.writeHeader(type: .ServerKeyExchange, bodyLength: self.encryptedPreMasterSecret.count + 2, target: &target)
        write(target, UInt16(self.encryptedPreMasterSecret.count))
        write(target, self.encryptedPreMasterSecret)
    }
}
