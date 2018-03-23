//
//  TLSNewSessionTicket.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 16.03.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSNewSessionTicket : TLSHandshakeMessage
{
    let ticketLifetime: UInt32
    let ticketAgeAdd: UInt32
    let ticketNonce: [UInt8]
    let ticket: [UInt8]
    let extensions: [TLSExtension]
    
    init(ticketLifetime: UInt32, ticketAgeAdd: UInt32, ticketNonce: [UInt8], ticket: [UInt8], extensions: [TLSExtension])
    {
        self.ticketLifetime = ticketLifetime
        self.ticketAgeAdd = ticketAgeAdd
        self.ticketNonce = ticketNonce
        self.ticket = ticket
        
        self.extensions = extensions
        
        super.init(type: .handshake(.newSessionTicket))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.newSessionTicket else {
            return nil
        }
        
        let bytesStart = inputStream.bytesRead
        
        guard
            let ticketLifetime: UInt32 = inputStream.read(),
            let ticketAgeAdd: UInt32 = inputStream.read(),
            let ticketNonce: [UInt8] = inputStream.read8(),
            let ticket: [UInt8] = inputStream.read16()
        else {
                return nil
        }
        
        self.ticketLifetime = ticketLifetime
        self.ticketAgeAdd = ticketAgeAdd
        self.ticketNonce = ticketNonce
        self.ticket = ticket

        let bytesLeft = bodyLength - (inputStream.bytesRead - bytesStart)
        if let extensions = TLSReadExtensions(from: inputStream, length: bytesLeft, messageType: .newSessionTicket) {
            self.extensions = extensions
        }
        else {
            self.extensions = []
        }
        
        super.init(type: .handshake(.newSessionTicket))
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        var data = DataBuffer()
        
        data.write(self.ticketLifetime)
        data.write(self.ticketAgeAdd)
        data.write(UInt8(self.ticketNonce.count))
        data.write(self.ticketNonce)
        data.write(UInt16(self.ticket.count))
        data.write(self.ticket)

        TLSWriteExtensions(&data, extensions: self.extensions, messageType: .newSessionTicket)
        
        self.writeHeader(type: .newSessionTicket, bodyLength: data.buffer.count, target: &target)
        target.write(data.buffer)
    }
}
