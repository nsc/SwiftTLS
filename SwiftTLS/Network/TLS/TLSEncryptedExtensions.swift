//
//  TLSEncryptedExtensions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 18.02.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSEncryptedExtensions : TLSHandshakeMessage
{
    var extensions: [TLSExtension] = []
    
    init(extensions: [TLSExtension])
    {
        self.extensions = extensions
        
        super.init(type: .handshake(.encryptedExtensions))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.encryptedExtensions else {
            return nil
        }
        
        if let extensions = TLSReadExtensions(from: inputStream, length: bodyLength, messageType: .serverHello) {
            self.extensions = extensions
        }
        
        super.init(type: .handshake(.encryptedExtensions))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        var data = DataBuffer()
        TLSWriteExtensions(&data, extensions: self.extensions)
        
        self.writeHeader(type: .encryptedExtensions, bodyLength: data.buffer.count, target: &target)
        target.write(data.buffer)
    }
}
