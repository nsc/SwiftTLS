//
//  TLSHelloRetryRequest.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 17.04.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

let helloRetryRequestRandom = Random([
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
] as [UInt8])!

class TLSHelloRetryRequest : TLSServerHello
{
    init(serverVersion: TLSProtocolVersion, cipherSuite: CipherSuite, extensions: [TLSExtension])
    {
        super.init(serverVersion: serverVersion, random: helloRetryRequestRandom, cipherSuite: cipherSuite)
        
        self.extensions = extensions
    }

    override var type : TLSMessageType {
        return .handshake(handshakeType)
    }
    
    override var handshakeType: TLSHandshakeType {
        return .helloRetryRequest
    }
    
    convenience init(_ serverHello: TLSServerHello)
    {
        self.init(serverVersion: serverHello.legacyVersion,
                  cipherSuite: serverHello.cipherSuite,
                  extensions: serverHello.extensions)
        
        self.legacySessionID = serverHello.legacySessionID
    }
    
    required init?(inputStream: InputStreamType, context: TLSConnection) {
        fatalError("HelloRetryRequest is never directly constructed from an input stream, since the handshake type is serverHello.")
    }
    
}
