//
//  TLS1_3.TicketStorage.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.03.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    // The maximum amount we allow the clients view of a tickets age to be off in milliseconds
    static let maximumAcceptableTicketAgeOffset: UInt32 = 10_000
    
    struct Ticket
    {
        var serverNames: [String]
        var identity: [UInt8]
        var nonce: [UInt8]
        var lifeTime: UInt32
        var ageAdd: UInt32
        
        var preSharedKey: [UInt8]!
        var hashAlgorithm: HashAlgorithm
        var cipherSuite: CipherSuite
        var maxEarlyDataSize: UInt32
        
        var creationDate: Date
        
        init(serverNames: [String],
             identity: [UInt8],
             nonce: [UInt8],
             lifeTime: UInt32,
             ageAdd: UInt32,
             cipherSuite: CipherSuite,
             maxEarlyDataSize: UInt32 = 0,
             hashAlgorithm: HashAlgorithm = .sha256)
        {
            self.serverNames = serverNames
            self.identity = identity
            self.nonce = nonce
            self.lifeTime = lifeTime
            self.ageAdd = ageAdd
            self.cipherSuite = cipherSuite
            self.maxEarlyDataSize = maxEarlyDataSize
            self.hashAlgorithm = hashAlgorithm
            
            self.creationDate = Date()
        }
        
        func isValid(at time: Date) -> Bool {
            let age = -creationDate.timeIntervalSince(time)
            
            return age <= Double(self.lifeTime)
        }
        
        internal mutating func derivePreSharedKey(for connection: TLSConnection, sessionResumptionSecret: [UInt8]) {
            self.preSharedKey = (connection.protocolHandler as! BaseProtocol).HKDF_Expand_Label(secret: sessionResumptionSecret, label: resumptionLabel, hashValue: self.nonce, outputLength: self.hashAlgorithm.hashLength)
        }
    }
    
    struct TicketStorage
    {
        typealias ServerNameToTicketsDictionary = [String : [Ticket]]
        
        var tickets: ServerNameToTicketsDictionary = [:]
        
        mutating func add(_ ticket: Ticket) {
            for serverName in ticket.serverNames {
                var tickets = self.tickets[serverName, default: []]
                tickets.append(ticket)
                
                self.tickets[serverName] = tickets
            }
            
//            log("Add ticket: \(self.tickets.debugDescription)")
        }
        
        mutating func remove(_ ticket: Ticket) {
            let now = Date()

            for serverName in ticket.serverNames {
                // Filter for valid tickets in order we clean up our cache whenever we remove a ticket
                var tickets = self.tickets[serverName, default: []].filter({$0.isValid(at: now)})
                if let index = tickets.firstIndex(where: {$0.identity == ticket.identity}) {
                    tickets.remove(at: index)
                }
                
                self.tickets[serverName] = tickets
            }
            
//            log("Remove ticket: \(self.tickets.debugDescription)")
        }
        
        subscript(serverName serverName: String) -> [Ticket] {
            return self.tickets[serverName] ?? []
        }
        
        mutating func removeInvalidTickets() {
            let now = Date()
            for serverName in tickets.keys {
                let tickets = self.tickets[serverName, default: []].filter({$0.isValid(at: now)})
                self.tickets[serverName] = tickets
            }
        }
    }
}

extension TLS1_3.Ticket : CustomDebugStringConvertible {
    var debugDescription: String {
        return """
        
        serverNames:    \(serverNames)
        identity:       \(hex(identity))
        nonce:          \(hex(nonce))
        lifeTime:       \(lifeTime)
        ageAdd:         \(ageAdd)
        cipherSuite:    \(cipherSuite)
        hashAlgorithm:  \(hashAlgorithm)
        """
    }
}
