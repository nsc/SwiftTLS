//
//  TLS1_3.TicketStorage.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.03.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class Ticket
    {
        var serverNames: [String]
        var identity: [UInt8]
        var nonce: [UInt8]
        var lifeTime: UInt32
        var ageAdd: UInt32
        
        var preSharedKey: [UInt8]!
        var hashAlgorithm: HashAlgorithm
        var cipherSuite: CipherSuite
        
        init(serverNames: [String],
             identity: [UInt8],
             nonce: [UInt8],
             lifeTime: UInt32,
             ageAdd: UInt32,
             cipherSuite: CipherSuite,
             hashAlgorithm: HashAlgorithm = .sha256)
        {
            self.serverNames = serverNames
            self.identity = identity
            self.nonce = nonce
            self.lifeTime = lifeTime
            self.ageAdd = ageAdd
            self.cipherSuite = cipherSuite
            self.hashAlgorithm = hashAlgorithm
        }
        
        internal func derivePreSharedKey(for connection: TLSConnection, sessionResumptionSecret: [UInt8]) {
            self.preSharedKey = (connection.protocolHandler as! BaseProtocol).HKDF_Expand_Label(secret: sessionResumptionSecret, label: resumptionLabel, hashValue: self.nonce, outputLength: self.hashAlgorithm.hashLength)
        }
    }
    
    class TicketStorage
    {
        typealias ServerNameToTicketsDictionary = [String : [Ticket]]
        
        var tickets: ServerNameToTicketsDictionary = [:]
        
        func add(_ ticket: Ticket) {
            for serverName in ticket.serverNames {
                var tickets = self.tickets[serverName, default: []]
                tickets.append(ticket)
                
                self.tickets[serverName] = tickets
            }
        }
        
        func remove(_ ticket: Ticket) {
            for serverName in ticket.serverNames {
                var tickets = self.tickets[serverName, default: []]
                if let index = tickets.index(where: {$0 === ticket}) {
                    tickets.remove(at: index)
                }
                
                self.tickets[serverName] = tickets
            }
        }
        
        subscript(serverName serverName: String) -> [Ticket] {
            return self.tickets[serverName] ?? []
        }
    }
}
