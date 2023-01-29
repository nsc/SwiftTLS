//
//  TLS1_3.ServerProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ServerHandshakeState : HandshakeState {
        enum EarlyDataState {
            case none
            case rejected
            case accepted
        }
        
        var serverEarlyDataState: EarlyDataState = .none
    }

    class ServerProtocol : BaseProtocol, TLSServerProtocol {
        init(server: TLSServer) {
            super.init(connection: server)
        }

        func acceptConnection(withClientHello clientHello: TLSClientHello?) async throws {
            var hasSentHelloRetry = false
            
            // When the client hello does not have a key share for a key exchange
            // that we support, the server needs to send a hello retry once with
            // a supported key share. The client then sends another client hello
            // which must match. If it doesn't the handshake is aborted.
            repeat {
                let clientHello = try await handle(receive(TLSClientHello.self))
                
                if server.negotiatedProtocolVersion != .v1_3 {
                    // when we have fallen back to a lesser version,
                    // the protocol handler for that version has already
                    // completed the handshake
                    return
                }
                
                if self.server!.cipherSuite == nil {
                    if hasSentHelloRetry {
                        // abort handshake if after the second client hello
                        // we still couldn't agree on a cipher suite
                        try await server.abortHandshake()
                    }
                    
                    try await sendHelloRetryRequest(for: clientHello)
                    hasSentHelloRetry = true
                    continue
                }
                else {
                    try await sendServerHello(for: clientHello)
                }
                
                try await sendEncryptedExtensions()
                
                if isUsingPreSharedKey {
                    try await sendFinished()
                }
                else {
                    try await sendCertificate()
                    try await sendCertificateVerify()
                    try await sendFinished()
                }
                
                try await handle(receive(TLSFinished.self))
                
                if self.server!.configuration.supportsSessionResumption && !(self.server!.serverNames?.isEmpty ?? true)  {
                    try await sendNewSessionTicket()
                }
                
                break
            } while (true)
        }

        func receiveClientHello() async throws -> TLSClientHello {
            guard let message = try await server.receiveNextTLSMessage() as? TLSClientHello else {
                try await server.abortHandshake(with: .handshakeFailure)
            }
            
            return message
        }

        func receiveFinished() async throws -> TLSFinished {
            guard let message = try await server.receiveNextTLSMessage() as? TLSFinished else {
                try await server.abortHandshake(with: .handshakeFailure)
            }
            
            return message
        }

        func sendServerHello(for clientHello: TLSClientHello) async throws {
            let serverHelloRandom = Random()
            let serverHello = TLSServerHello(
                serverVersion: .v1_2,
                random: serverHelloRandom,
                sessionID: clientHello.legacySessionID,
                cipherSuite: server.cipherSuite!,
                compressionMethod: .null)

            guard let clientKeyShare = server.clientKeyShare else {
                throw TLSError.error("Client Key Share not established in sendServerHello")
            }
            
            var keyExchange = clientKeyShare.namedGroup.keyExchange.pfsKeyExchange!
            keyExchange.createKeyPair()
            keyExchange.peerPublicKey = clientKeyShare.keyExchange
            
            let serverKeyShare = KeyShareEntry(namedGroup: clientKeyShare.namedGroup, keyExchange: keyExchange.publicKey!)
            let keyShareExtension = TLSKeyShareExtension(keyShare: .serverHello(serverShare: serverKeyShare))
            serverHello.extensions.append(keyShareExtension)
            
            let supportedVersions = TLSSupportedVersionsExtension(supportedVersions: [server.negotiatedProtocolVersion!])
            serverHello.extensions.append(supportedVersions)
            
            if self.serverHandshakeState.serverEarlyDataState == .accepted {
                deriveEarlyTrafficSecret()
            }
            
            if let selectedIdentity = self.handshakeState.selectedIdentity {
                serverHello.extensions.append(TLSPreSharedKeyExtension(preSharedKey: .serverHello(selectedIdentity)))
            }
            
            // Normally we would use sendHandshakeMessage here, which would implicitly add the message to
            // the handShakeMessages and didSendHandshakeMessage on the stateMachine.
            // But since that would immediately trigger the sending of EncryptedExtensions, we have no chance
            // to establish the encryption keys inbetween.
            // So until we can come up with a different architecture to do this, we are doing the three
            // steps here by hand, intermixed with establishing the encryption keys
            try await server.sendMessage(serverHello)
            server.handshakeMessages.append(serverHello)
            
            deriveEarlySecret()
            deriveHandshakeSecret(with: keyExchange)
            
            self.recordLayer.changeKeys(withClientTrafficSecret: self.handshakeState.clientHandshakeTrafficSecret!,
                                        serverTrafficSecret: self.handshakeState.serverHandshakeTrafficSecret!)

        }
        
        func sendEncryptedExtensions() async throws {
            var extensions: [TLSExtension] = []
            if case .accepted = self.serverHandshakeState.serverEarlyDataState {
                extensions.append(TLSEarlyDataIndication())
            }
            
            let encryptedExtensions = TLSEncryptedExtensions(extensions: extensions)
            try await server.sendHandshakeMessage(encryptedExtensions)
        }
        
        @discardableResult
        func handle(_ clientHello: TLSClientHello) async throws -> TLSClientHello {

            guard let negotiatedProtocolVersion = selectVersion(for: clientHello) else {
                try await server.abortHandshake()
            }
            
            guard negotiatedProtocolVersion >= .v1_3_draft26 else {
                if let supportdVersions = clientHello.extensions.filter({$0 is TLSSupportedVersionsExtension}).first as? TLSSupportedVersionsExtension {
                    log("Client is only supporting \(supportdVersions.supportedVersions)")
                }
                else {
                    log("Client is only supporting \(clientHello.legacyVersion)")
                }
                
                log("Falling back to \(negotiatedProtocolVersion)")
                
                // fallback to lesser version
                server.setupServer(with: self.server.configuration, version: negotiatedProtocolVersion)
                
                try await server.serverProtocolHandler.acceptConnection(withClientHello: clientHello)
                
                return clientHello
            }
            
            server.negotiatedProtocolVersion = negotiatedProtocolVersion
            
            var clientPSKKeyExchangeModes: [PSKKeyExchangeMode]? = nil
            var clientKeyShares: [KeyShareEntry]? = nil
            var clientOfferedPSKs: OfferedPSKs? = nil
            
            for clientExtension in clientHello.extensions {
                switch clientExtension.extensionType {
                case .serverName:
                    self.connection.serverNames = (clientExtension as! TLSServerNameExtension).serverNames

                case .keyShare:
                    if case .clientHello(let keyShares) = (clientExtension as! TLSKeyShareExtension).keyShare {
                        clientKeyShares = keyShares
                    }
                    
                case .pskKeyExchangeModes:
                    clientPSKKeyExchangeModes = (clientExtension as! TLSPSKKeyExchangeModesExtension).keyExchangeModes
                    
                case .preSharedKey:
                    if case .clientHello(let offeredPSKs) = (clientExtension as! TLSPreSharedKeyExtension).preSharedKey {
                        clientOfferedPSKs = offeredPSKs
                    }
                    
                case .earlyData:
                    if case .supported(let maxEarlyDataSize) = self.server.configuration.earlyData {
                        
                        if maxEarlyDataSize > 0 {
                            self.serverHandshakeState.serverEarlyDataState = .accepted
                        }
                        else {
                            self.server.configuration.earlyData = .notSupported
                        }
                    }

                default:
                    break
                }
            }
            
            guard let cipherSuite = server.selectCipherSuite(clientHello.cipherSuites) else {
                try await server.sendAlert(.handshakeFailure, alertLevel: .fatal)
                throw TLSError.error("No shared cipher suites. Client supports:" + clientHello.cipherSuites.map({"\($0)"}).reduce("", {$0 + "\n" + $1}))
            }
            
            log("Selected cipher suite is \(cipherSuite)")
            
            guard let keyShares = clientKeyShares,
                let keyShare = selectKeyShare(fromClientKeyShares: keyShares)
                else {
                    
                    // Return without setting cipher suite and key share. The state machine
                    // will send a retry request if possible.
                    return clientHello
            }

            // Set cipher suite. The transcript hash is using the hash function
            // configured here.
            server.cipherSuite = cipherSuite
            server.clientKeyShare = keyShare

            // FIXME: Check that the combination of offered extensions for key share and PSKs is sane
            if let offeredPSKs = clientOfferedPSKs {
                guard clientPSKKeyExchangeModes != nil else {
                    try await server.abortHandshake()
                }
                
                guard offeredPSKs.binders.count == offeredPSKs.identities.count else {
                    try await server.abortHandshake(with: .illegalParameter)
                }
                
                let bindersSize = offeredPSKs.bindersNetworkSize
                let truncatedTranscriptHash = self.connection.transcriptHashWithTruncatedClientHello(droppingLast: bindersSize)
                
                var chosenTicket: Ticket? = nil
                for i in 0..<offeredPSKs.identities.count {
                    let identity = offeredPSKs.identities[i]
                    
                    if let ticket = self.ticketsForCurrentConnection(at: Date()).filter({$0.identity == identity.identity}).first {
                        let ticketAge = UInt32(Date().timeIntervalSince(ticket.creationDate) * 1000)
                        let identityAge = identity.obfuscatedTicketAge &- ticket.ageAdd
                        
                        log("Server ticket age      : \(ticketAge)")
                        log("Client ticket age      : \(identityAge)")
                        log("ticket hash algorithm  : \(ticket.hashAlgorithm)")
                        
                        // Reject ticket if the clients view of the ticket age is too far off
                        guard identityAge < ticketAge + maximumAcceptableTicketAgeOffset else {
                            continue
                        }
                        
                        self.handshakeState.preSharedKey = ticket.preSharedKey
                        deriveEarlySecret()
                        self.handshakeState.resumptionBinderSecret = deriveResumptionPSKBinderSecret()
                        
                        let binderKey = deriveBinderKey()
                        
                        let binderValue = binderValueWithHashAlgorithm(ticket.hashAlgorithm, binderKey: binderKey, transcriptHash: truncatedTranscriptHash)
                        
                        let binder = offeredPSKs.binders[i]
                        
                        if binder.binder == binderValue {
                            chosenTicket = ticket
                            self.handshakeState.preSharedKey = ticket.preSharedKey
                            self.handshakeState.selectedIdentity = UInt16(i)

                            // Remove ticket from cache to prevent replay attacks
                            // (see RFC 8446, section 8.1 Single-Use Tickets)
                            self.context.ticketStorage.remove(ticket)

                            break
                        }
                        else {
                            log("Binder value mismatch for identity \(identity)")
                        }
                    }
                }
                
                if let ticket = chosenTicket {
                    currentTicket = ticket
                    log("Choose ticket \(ticket.identity)")
                }
            }
            
            if currentTicket == nil {
                self.serverHandshakeState.serverEarlyDataState = .rejected
                self.handshakeState.preSharedKey = nil
                self.handshakeState.resumptionBinderSecret = nil
            }

            if case .accepted = self.serverHandshakeState.serverEarlyDataState {
                assert(self.serverHandshakeState.preSharedKey != nil)
            }
            
            return clientHello
        }
        
        func sendHelloRetryRequest(for clientHello: TLSClientHello) async throws
        {
            guard let cipherSuite = server.selectCipherSuite(clientHello.cipherSuites) else {
                try await server.abortHandshake()
            }
            
            guard let supportedGroupsExtension = clientHello.extensions.filter({$0 is TLSSupportedGroupsExtension}).first else {
                try await server.abortHandshake()
            }
            
            let supportedGroups = (supportedGroupsExtension as! TLSSupportedGroupsExtension).ellipticCurves
            let commonGroups: [NamedGroup] = self.server.configuration.supportedGroups.filter({supportedGroups.contains($0)})
            
            guard commonGroups.count > 0 else {
                try await server.abortHandshake()
            }
            
            let extensions: [TLSExtension] = [
                TLSSupportedVersionsExtension(supportedVersions: [server!.negotiatedProtocolVersion!]),
                TLSKeyShareExtension(keyShare: .helloRetryRequest(selectedGroup: commonGroups[0]))
            ]
            
            let helloRetryRequest = TLSHelloRetryRequest(serverVersion: TLSProtocolVersion.v1_2, cipherSuite: cipherSuite, extensions: extensions)
            helloRetryRequest.legacySessionID = clientHello.legacySessionID
            
            try await server.sendHandshakeMessage(helloRetryRequest)
        }

        override func sendFinished() async throws {
            let verifyData = finishedData(forClient: connection.isClient)
            
            try await connection.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
                        
            // The secret contains all the handshake messages up to Server Finished, so the server has to derive
            // it after sending its Finished
            deriveApplicationTrafficSecrets()

            log("Server: activate server traffic secret")
            recordLayer.changeWriteKeys(withTrafficSecret: self.handshakeState.serverTrafficSecret!)

            if case .accepted = serverHandshakeState.serverEarlyDataState {
                server.earlyDataWasAccepted = true

                activateEarlyTrafficSecret()
                
                // Read until EndOfEarlyData
                EndOfEarlyDataLoop: while true {
                    let message = try await recordLayer.readMessage()
                    log("Server: did receive early data: \(String(describing: message))")
                    
                    switch message
                    {
                    case is TLSEndOfEarlyData:
                        server.handshakeMessages.append(message as! TLSEndOfEarlyData)
                        break EndOfEarlyDataLoop
                        
                    case is TLSApplicationData:
                        let data = (message as! TLSApplicationData).applicationData
                        if let earlyDataResponseHandler = server.earlyDataResponseHandler {
                            if let response = await earlyDataResponseHandler(self.server, Data(data)) {
                                var buffer = [UInt8](repeating: 0, count: response.count)
                                buffer.withUnsafeMutableBufferPointer {
                                    _ = response.copyBytes(to: $0)
                                }
                                
                                log("Server: sending \(buffer.count) bytes of early data")
                                
                                try await server.sendApplicationData(buffer)
                            }
                        }
                        else {
                            server.earlyData = data
                        }
                        
                        break

                    case is TLSChangeCipherSpec:
                        // FIXME: Check if this is legal. OpenSSL seems to send
                        // a ChangeCipherSpec in its early data
                        break
                        
                    default:
                        try await server.abortHandshake(with: .unexpectedMessage)
                    }
                }
                
                recordLayer.changeReadKeys(withTrafficSecret: handshakeState.clientHandshakeTrafficSecret!)
            }
            else {
                server.earlyDataWasAccepted = false
            }
        }

        func sendNewSessionTicket() async throws {
            guard let serverNames = self.connection.serverNames else {
                fatalError("Trying to sent NewSessionTicket, when the client didn't specify a server name")
            }

            let identity = TLSRandomBytes(count: 32)
            let ageAdd = UInt32(bigEndianBytes: TLSRandomBytes(count: 4))!
            // Currently we are sending only one session ticket per connection. If we want to support more than one, we would need
            // to chance the nonce here.
            var ticket = Ticket(serverNames: serverNames, identity: identity, nonce: [0], lifeTime: 3600, ageAdd: ageAdd, cipherSuite: server.cipherSuite!, hashAlgorithm: server.hashAlgorithm)

            deriveSessionResumptionSecret()
            ticket.derivePreSharedKey(for: connection, sessionResumptionSecret: self.handshakeState.sessionResumptionSecret!)
            
            self.context.ticketStorage.add(ticket)
            
            var extensions: [TLSExtension] = []
            if case .supported(let maxEarlyDataSize) = self.connection.configuration.earlyData {
                extensions.append(TLSEarlyDataIndication(maxEarlyDataSize: maxEarlyDataSize))
            }
            
            try await server.sendHandshakeMessage(TLSNewSessionTicket(ticket: ticket, extensions: extensions), appendToTranscript: false)
        }
        
        func handle(_ finished: TLSFinished) throws {
            // Verify finished data
            let finishedData = finishedData(forClient: true)
            if finishedData != finished.verifyData {
                log("Server error: could not verify Finished message.")
                throw TLSError.alert(.decryptError, alertLevel: .fatal)
            }
                
            server.handshakeMessages.append(finished)

            // Activate the application traffic secret after Client Finished
            log("Server: Activate client traffic secret")
            recordLayer.changeReadKeys(withTrafficSecret: self.handshakeState.clientTrafficSecret!)
        }
                
        func selectVersion(for clientHello: TLSClientHello) -> TLSProtocolVersion? {
            var supportedVersions: [TLSProtocolVersion]? = nil
            if let supportedVersionsExtension = clientHello.extensions.first(where: { $0 is TLSSupportedVersionsExtension }) as? TLSSupportedVersionsExtension {
                supportedVersions = supportedVersionsExtension.supportedVersions
            }
            
            var protocolVersion: TLSProtocolVersion? = nil
            if supportedVersions != nil {
                // This is a TLS >= 1.3 handshake so the supportedVersions are exhaustive
                for version in supportedVersions! {
                    if server.configuration.supports(version) {
                        protocolVersion = version
                        break
                    }
                }
            }
            else {
                // Legacy handshake
                let clientVersion = clientHello.legacyVersion
                if server.configuration.supports(clientVersion) {
                    protocolVersion = clientVersion
                }
                else {
                    let maxVersion = server.configuration.maximumSupportedVersion
                    
                    if clientVersion >= maxVersion {
                        protocolVersion = maxVersion
                    }
                }
            }
            
            return protocolVersion
        }
        
        func selectKeyShare(fromClientKeyShares keyShares: [KeyShareEntry]) -> KeyShareEntry?
        {
            for keyShare in keyShares {
                if server.configuration.supportedGroups.contains(keyShare.namedGroup) {
                    return keyShare
                }
            }

            return nil
        }
        
        var connectionInfo: String {
            var info = ""
            if let ticket = self.currentTicket {
                info += "Ticket:\n\(ticket)\n"
            }
            
            if connection.earlyDataWasAccepted {
                info += "Early Data:     Accepted\n"
            }

            return info
        }
        
        weak var server: TLSServer! {
            return (self.connection as! TLSServer)
        }

        var serverContext: TLSServerContext {
            return self.connection.context as! TLSServerContext
        }

        var serverHandshakeState: ServerHandshakeState {
            return self.handshakeState as! ServerHandshakeState
        }

        var currentTicket: Ticket?
        
        override func reset() {
            self.handshakeState = ServerHandshakeState()
        }
    }
}
