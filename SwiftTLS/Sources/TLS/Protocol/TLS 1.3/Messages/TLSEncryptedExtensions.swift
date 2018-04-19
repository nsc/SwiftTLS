//
//  TLSEncryptedExtensions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 18.02.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
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
            
            self.extensions = TLSReadExtensions(from: inputStream, length: bodyLength, messageType: .encryptedExtensions, context: context)
            
            super.init(type: .handshake(.encryptedExtensions))
        }
        
        override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
        {
            var data = [UInt8]()
            TLSWriteExtensions(&data, extensions: self.extensions, messageType: .encryptedExtensions, context: context)
            
            self.writeHeader(type: .encryptedExtensions, bodyLength: data.count, target: &target)
            target.write(data)
        }
    }
}
