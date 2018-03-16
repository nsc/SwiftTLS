//
//  TLSHelloRetryRequest.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 17.04.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSHelloRetryRequest : TLSHandshakeMessage
{
    let serverVersion: TLSProtocolVersion
    let cipherSuite: CipherSuite
    let extensions: [TLSExtension]
    
    init(serverVersion: TLSProtocolVersion, cipherSuite: CipherSuite, extensions: [TLSExtension])
    {
        self.serverVersion = serverVersion
        self.cipherSuite = cipherSuite
        self.extensions = extensions
        
        super.init(type: .handshake(.helloRetryRequest))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.helloRetryRequest else {
            return nil
        }
        
        guard
            let version = TLSProtocolVersion(inputStream: inputStream),
            let rawCipherSuite: UInt16 = inputStream.read(),
            let cipherSuite = CipherSuite(rawValue: rawCipherSuite)
        else {
            return nil
        }
        
        if let extensions = TLSReadExtensions(from: inputStream, length: bodyLength, messageType: .serverHello) {
            self.extensions = extensions
        }
        else {
            self.extensions = []
        }
        
        self.serverVersion = version
        self.cipherSuite = cipherSuite
        
        super.init(type: .handshake(.helloRetryRequest))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        var data = DataBuffer()
        data.write(self.serverVersion.rawValue)
        data.write(self.cipherSuite.rawValue)
        TLSWriteExtensions(&data, extensions: self.extensions)
        
        self.writeHeader(type: .helloRetryRequest, bodyLength: data.buffer.count, target: &target)
        target.write(data.buffer)
    }
}
