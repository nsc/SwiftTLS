//
//  TLS1_3.ClientProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ClientHandshakeState : HandshakeState {
        enum ClientEarlyDataState {
            case none
            case sent
            case accepted
            case rejected
        }
        var earlyDataState: ClientEarlyDataState = .none
    }
    
    class ClientProtocol : BaseProtocol, TLSClientProtocol {
        weak var client: TLSClient! {
            return (self.connection as! TLSClient)
        }
        
        var clientContext: TLSClientContext {
            return self.connection.context as! TLSClientContext
        }
        
        var clientHandshakeState: ClientHandshakeState {
            return self.handshakeState as! ClientHandshakeState
        }
        
        // We need to remember this in case the server wants to fallback to
        // a TLS version < 1.3. In that case we need to switch to a different
        // protocol handler and hand it the client hello random
        var clientHelloRandom: Random?
        
        var selectedGroupFromHelloRetryRequest: NamedGroup?
        
        var offeredPsks: OfferedPSKs? = nil
        
        var keyExchangesAnnouncedToServer: [NamedGroup : KeyExchange] = [:]
        var pskKeyExchangeModesAnnouncedToServer: [PSKKeyExchangeMode] = []
        var ticketsAnnouncedToServer: [Ticket] = []

        init(client: TLSClient)
        {
            super.init(connection: client)
        }
        
        override func reset() {
            self.handshakeState = ClientHandshakeState()
        }
        
        func sendClientHello() throws
        {
            let cipherSuites = client.configuration.cipherSuites
            clientHelloRandom = Random()
            let clientHello = TLSClientHello(
                configuration: client.configuration,
                random: clientHelloRandom!,
                sessionID: client.pendingSessionID,
                cipherSuites: cipherSuites,
                compressionMethods: [.null])
            
            if client.serverNames != nil {
                clientHello.extensions.append(TLSServerNameExtension(serverNames: client.serverNames!))
            }
            
            guard client.configuration.supportedGroups.count > 0 else {
                throw TLSError.error("TLS 1.3 configuration is missing supported key shares.")
            }
            
            let groups = client.configuration.supportedGroups
            
            clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: groups))
            
            var keyShareEntries : [KeyShareEntry] = []
            
//            if let group = self.selectedGroupFromHelloRetryRequest {
//                if let curve = EllipticCurve.named(group) {
//                    let keyExchange = ECDHKeyExchange(curve: curve)
//                    let Q = keyExchange.calculatePublicKeyPoint()
//
//                    let data = [UInt8](Q)
//                    keyShareEntries.append(KeyShareEntry(namedGroup: group, keyExchange: data))
//
//                    self.keyExchangesAnnouncedToServer[group] = .ecdhe(keyExchange)
//                }

            // Add key shares for all supported groups (Maybe we want to do this only for the most likely one?)
            for group in groups {
                
                if let curve = EllipticCurve.named(group) {
                    let keyExchange = ECDHKeyExchange(curve: curve)
                    let Q = keyExchange.calculatePublicKeyPoint()
                    
                    let data = [UInt8](Q)
                    keyShareEntries.append(KeyShareEntry(namedGroup: group, keyExchange: data))
                    
                    self.keyExchangesAnnouncedToServer[group] = .ecdhe(keyExchange)
                }
            }
            
            
            clientHello.extensions.append(TLSSignatureAlgorithmsExtension(signatureAlgorithms: [.rsa_pkcs1_sha256, .rsa_pss_sha256]))
            clientHello.extensions.append(TLSKeyShareExtension(keyShare: .clientHello(clientShares: keyShareEntries)))

            let now = Date()
            var isSendingEarlyData = false
            let tickets = self.ticketsForCurrentConnection(at: now)
            if tickets.count > 0 {
                self.pskKeyExchangeModesAnnouncedToServer = [.psk_dhe]
                clientHello.extensions.append(TLSPSKKeyExchangeModesExtension(keyExchangeModes: self.pskKeyExchangeModesAnnouncedToServer))
                
                let ticket = tickets.first!
                self.handshakeState.preSharedKey = ticket.preSharedKey

                // Derive secret for early data. If the server doesn't accept our pre-shard key, we will create it again in handleServerHello
                // without a pre-shared key
                deriveEarlySecret()
                self.handshakeState.resumptionBinderSecret = deriveResumptionPSKBinderSecret()
                                
                if self.client.earlyData != nil {
                    if case .supported(var maxEarlyDataSize) = self.client.configuration.earlyData {
                        maxEarlyDataSize = min(maxEarlyDataSize, ticket.maxEarlyDataSize)
                        
                        isSendingEarlyData = maxEarlyDataSize > 0
                        if isSendingEarlyData {
                            clientHello.extensions.append(TLSEarlyDataIndication())
                            self.client.cipherSuite = ticket.cipherSuite
                        }
                    }
                }

                // The PSK Extension needs to be the last extension
                if let preSharedKeyExtension = self.preSharedKeyExtension(for: clientHello, tickets: tickets) {
                    switch preSharedKeyExtension.preSharedKey {
                    case .clientHello(let offeredPsks):
                        self.offeredPsks = offeredPsks
                        clientHello.extensions.append(preSharedKeyExtension)
                        
                        self.ticketsAnnouncedToServer = tickets
                        
                    default:
                        fatalError("PreSharedKeyExtension must be clientHello")
                    }
                }
            }
            else {
                log("Client: No tickets for current connection")
            }

            try client.sendHandshakeMessage(clientHello)
            if isSendingEarlyData {
                if let earlyData = self.client.earlyData {
                    try sendEarlyData(earlyData)
                }
            }
        }
        
        func sendEarlyData(_ earlyData: [UInt8]) throws {
            deriveEarlyTrafficSecret()
            activateEarlyTrafficSecret()
            
            log("Client: did send early data")
            
            try client.sendApplicationData(earlyData)
        }
        
        func preSharedKeyExtension(for clientHello: TLSClientHello,
                                   tickets: [Ticket],
                                   withFakeBinders fakeBinders: Bool = false) -> TLSPreSharedKeyExtension? {
            
            guard tickets.count > 0 else {
                return nil
            }
            
            var identities: [PSKIdentity] = []
            var binders: [PSKBinderEntry] = []
            
            let binderKey = deriveBinderKey()

            for ticket in tickets {
                let ticketAge = -ticket.creationDate.timeIntervalSince(Date())
                guard ticketAge > 0 && ticketAge < Double(ticket.lifeTime) else {
                    continue
                }
                
                identities.append(PSKIdentity(identity: ticket.identity,
                                              obfuscatedTicketAge: ((UInt32(ticketAge) &* 1000) &+ ticket.ageAdd)))
                
                var binder: [UInt8]
                if fakeBinders {
                    binder = [UInt8](repeating: 0, count: ticket.hashAlgorithm.hashLength)
                }
                else {
                    let truncatedClientHelloData = self.truncatedClientHelloDataForPSKBinders(for: clientHello, tickets: tickets)
                    let truncatedTranscriptData = self.connection.handshakeMessageData + truncatedClientHelloData
                    let transcriptHash = self.connection.hashAlgorithm.hashFunction(truncatedTranscriptData)
                    
                    binder = binderValueWithHashAlgorithm(ticket.hashAlgorithm, binderKey: binderKey, transcriptHash: transcriptHash)
                }
                
                binders.append(PSKBinderEntry(binder: binder))
            }
            
            return TLSPreSharedKeyExtension(preSharedKey: .clientHello(OfferedPSKs(identities: identities, binders: binders)))
        }
        
        func truncatedClientHelloDataForPSKBinders(for clientHello: TLSClientHello, tickets: [Ticket]) -> [UInt8] {
            guard let preSharedKeyExtension = self.preSharedKeyExtension(for: clientHello, tickets: tickets, withFakeBinders: true) else {
                fatalError("No pre-shared keys to put into extension")
            }
            
            let bindersSize: Int
            switch preSharedKeyExtension.preSharedKey {
            case .clientHello(let offeredPSKs):
                bindersSize = offeredPSKs.bindersNetworkSize
                
            default:
                fatalError()
            }
            
            clientHello.extensions.append(preSharedKeyExtension)
            
            let clientHelloData = clientHello.messageData(with: self.connection)
            let truncatedClientHelloData = clientHelloData.dropLast(bindersSize)
            
            clientHello.extensions.removeLast()
            
            return [UInt8](truncatedClientHelloData)
        }
        
        func handleServerHello(_ serverHello: TLSServerHello) throws {
            guard serverHello.version == .v1_3 else {
        
                // If the server does not support TLS 1.3, fall back to lower version
                // if the configuration supports it
        
                if !client.configuration.supports(serverHello.version) {
                    try client.abortHandshake()
                }
                
                switch serverHello.version {
                case TLSProtocolVersion.v1_2:
                    client.setupClient(with: .v1_2)
                    let protocolHandler = client.protocolHandler as! TLS1_2.ClientProtocol
                    protocolHandler.securityParameters.clientRandom = [UInt8](self.clientHelloRandom!)
                    try client.clientProtocolHandler.handleServerHello(serverHello)
                    
                default:
                    try client.abortHandshake()
                }
                
                return
            }
            
            log("Server wants to speak \(serverHello.version)")

            if let helloRetryRequest = serverHello as? TLSHelloRetryRequest {
                try self.handleHelloRetryRequest(helloRetryRequest)
                
                return
            }

            client.recordLayer?.protocolVersion = .v1_3
            client.negotiatedProtocolVersion    = .v1_3
            
            client.cipherSuite = serverHello.cipherSuite

            var keyExchangeChosenByServer: PFSKeyExchange? = nil
            var ticketChosenByServer: Ticket? = nil
            
            for serverExtension in serverHello.extensions {
                switch serverExtension.extensionType {
                case .preSharedKey:
                    if case .serverHello(let selectedIdentity) = (serverExtension as! TLSPreSharedKeyExtension).preSharedKey {
                        guard selectedIdentity < self.ticketsAnnouncedToServer.count else {
                            throw TLSError.alert(alert: .illegalParameter, alertLevel: .fatal)
                        }
                        
                        ticketChosenByServer = self.ticketsAnnouncedToServer[Int(selectedIdentity)]
                    }
                    else {
                        // FIXME: Is this the right error to throw here? What does the RFC say about it?
                        throw TLSError.alert(alert: .decodeError, alertLevel: .fatal)
                    }

                case .keyShare:
                    if case .serverHello(let keyShare) = (serverExtension as! TLSKeyShareExtension).keyShare {
                        let group = keyShare.namedGroup
                        let peerPublicKey = keyShare.keyExchange
                        guard var keyExchange = self.keyExchangesAnnouncedToServer[group]?.pfsKeyExchange else {
                            throw TLSError.alert(alert: .illegalParameter, alertLevel: .fatal)
                        }

                        keyExchange.peerPublicKey = peerPublicKey
                        
                        keyExchangeChosenByServer = keyExchange
                    }
                    else {
                        // FIXME: Is this the right error to throw here? What does the RFC say about it?
                        throw TLSError.alert(alert: .decodeError, alertLevel: .fatal)
                    }
                    
                case .supportedVersions:
                    break
                    
                default:
                    log("Unhandled extension \(serverExtension)")
                }
            }
            
            if let ticket = ticketChosenByServer {
                log("Server has chosen ticket identity: \(hex(ticket.identity))")
                self.handshakeState.preSharedKey = ticket.preSharedKey
                self.context.ticketStorage.remove(ticket)
                deriveEarlySecret()
            }
            else {
                if self.ticketsAnnouncedToServer.count > 0 {
                    log("Server has ignored our ticket")
                }
                self.handshakeState.preSharedKey = nil

                deriveEarlySecret()
            }
            
            guard let keyExchange = keyExchangeChosenByServer else {
                throw TLSError.alert(alert: .illegalParameter, alertLevel: .fatal)
            }
            
            deriveHandshakeSecret(with: keyExchange)

            guard let serverHandShakeTrafficSecret = self.handshakeState.serverHandshakeTrafficSecret else {
                throw TLSError.alert(alert: .handshakeFailure, alertLevel: .fatal)
            }

            self.recordLayer.changeReadKeys(withTrafficSecret: serverHandShakeTrafficSecret)
        }
        
        func handleEncryptedExtensions(_ encryptedExtensions: TLSEncryptedExtensions) throws {
            log("EncryptedExtensions: \(encryptedExtensions.extensions)")
            
            if encryptedExtensions.extensions.contains(where: {$0 is TLSEarlyDataIndication}) {
                self.clientHandshakeState.earlyDataState = .accepted
            }
        }
        
        func handleHelloRetryRequest(_ helloRetryRequest: TLSHelloRetryRequest) throws {
            for helloRetryRequestExtension in helloRetryRequest.extensions {
                switch helloRetryRequestExtension.extensionType {
                case .keyShare:
                    if case .helloRetryRequest(let keyShare) = (helloRetryRequestExtension as! TLSKeyShareExtension).keyShare {
                        self.selectedGroupFromHelloRetryRequest = keyShare
                    }
                    else {
                        // FIXME: Is this the right error to throw here? What does the RFC say about it?
                        throw TLSError.alert(alert: .decodeError, alertLevel: .fatal)
                    }

                case .supportedVersions:
                    break
                    
                default:
                    log("Unhandled extension \(helloRetryRequestExtension)")

                }
            }
        }
        
        func handleNewSessionTicket(_ newSessionTicket: TLSNewSessionTicket) throws {
            guard let serverNames = self.client.serverNames else {
                fatalError("Client doesn't know the server it is connecting to.")
            }
            
            var ticket = Ticket(serverNames: serverNames,
                                identity: newSessionTicket.ticket,
                                nonce: newSessionTicket.ticketNonce,
                                lifeTime: newSessionTicket.ticketLifetime,
                                ageAdd: newSessionTicket.ticketAgeAdd,
                                cipherSuite: self.client.cipherSuite!,
                                maxEarlyDataSize: newSessionTicket.maxEarlyDataSize,
                                hashAlgorithm: self.client.hashAlgorithm)
            
            ticket.derivePreSharedKey(for: connection, sessionResumptionSecret: self.handshakeState.sessionResumptionSecret!)

            self.context.ticketStorage.add(ticket)
        }
        
        override func sendFinished() throws
        {            
            // The secret contains all the handshake messages up to Server Finished, so the client has to derive
            // it before sending its Finished
            deriveApplicationTrafficSecrets()

            if case .accepted = self.clientHandshakeState.earlyDataState {
                try self.connection.sendHandshakeMessage(TLSEndOfEarlyData())
            }

            let verifyData = self.finishedData(forClient: connection.isClient)
        
            guard let clientHandshakeTrafficSecret = self.handshakeState.clientHandshakeTrafficSecret else {
                fatalError("client handshake secret not derived when sending finished")
            }
            self.recordLayer.changeWriteKeys(withTrafficSecret: clientHandshakeTrafficSecret)
            
            try self.connection.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
            
            deriveSessionResumptionSecret()
            
            self.recordLayer.changeReadKeys(withTrafficSecret: self.handshakeState.serverTrafficSecret!)
            self.recordLayer.changeWriteKeys(withTrafficSecret: self.handshakeState.clientTrafficSecret!)
        }

        override func handleHandshakeMessage(_ handshakeMessage: TLSHandshakeMessage) throws -> Bool {
            guard try !super.handleHandshakeMessage(handshakeMessage) else {
                return true
            }
            
            switch handshakeMessage.handshakeType
            {
            case .encryptedExtensions:
                try self.handleEncryptedExtensions(handshakeMessage as! TLSEncryptedExtensions)
                
            case .newSessionTicket:
                try self.handleNewSessionTicket(handshakeMessage as! TLSNewSessionTicket)
                
            default:
                return false
            }
            
            return true
        }
        
        func handleFinished(_ finished: TLSFinished) throws {
            // Verify finished data
            let finishedData = self.finishedData(forClient: false)
            if finishedData != finished.verifyData {
                log("Client error: could not verify Finished message.")
                try client.sendAlert(.decryptError, alertLevel: .fatal)
            }
            
            client.handshakeMessages.append(finished)
        }
        
        var connectionInfo: String {
            return ""
        }

    }
}
