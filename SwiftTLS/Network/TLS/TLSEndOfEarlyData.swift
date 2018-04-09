//
//  TLSEndOfEarlyData.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 07.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    
    class TLSEndOfEarlyData : TLSHandshakeMessage {
        init()
        {
            super.init(type: .handshake(.endOfEarlyData))
        }
        
        required init?(inputStream : InputStreamType, context: TLSConnection)
        {
            guard let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == .endOfEarlyData,
                bodyLength == 0
            else {
                return nil
            }

            super.init(type: .handshake(.endOfEarlyData))
        }
    }
}
