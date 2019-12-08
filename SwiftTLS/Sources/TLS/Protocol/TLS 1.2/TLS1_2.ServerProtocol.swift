//
//  TLSServerProtocol1_2.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_2 {
    class ServerProtocol : BaseProtocol, TLSServerProtocol
    {
        weak var server: TLSServer! {
            return (self.connection as! TLSServer)
        }
        
        init(server: TLSServer)
        {
            super.init(connection: server)
        }
        
        var serverContext: TLSServerContext {
            return self.connection.context as! TLSServerContext
        }

        func sendServerHello(for clientHello: TLSClientHello) throws {
            var sessionID: TLSSessionID
            if let session = server.currentSession {
                sessionID = session.sessionID
            }
            else {
                // create new session id
                repeat {
                    sessionID = TLSSessionID.new()
                } while self.serverContext.sessionCache[sessionID] != nil
                
                server.pendingSessionID = sessionID
            }
            
            let serverHelloRandom = Random()
            let serverHello = TLSServerHello(
                serverVersion: server.negotiatedProtocolVersion!,
                random: serverHelloRandom,
                sessionID: sessionID,
                cipherSuite: server.cipherSuite!,
                compressionMethod: .null)
            
            if self.securityParameters.isUsingSecureRenegotiation {
                if server.isInitialHandshake {
                    serverHello.extensions.append(TLSSecureRenegotiationInfoExtension())
                }
                else {
                    let renegotiationInfo = self.securityParameters.clientVerifyData + self.securityParameters.serverVerifyData
                    serverHello.extensions.append(TLSSecureRenegotiationInfoExtension(renegotiatedConnection: renegotiationInfo))
                }
            }
            
            log("ServerHello extensions = \(serverHello.extensions)")
            
            self.securityParameters.serverRandom = [UInt8](serverHelloRandom)
            if let session = server.currentSession {
                self.setPendingSecurityParametersForCipherSuite(session.cipherSpec)
            }
            
            server.isInitialHandshake = false
            
            try server.sendHandshakeMessage(serverHello)
        }
        
        func sendServerHelloDone() throws
        {
            try server.sendHandshakeMessage(TLSServerHelloDone())
        }
        
        func sendServerKeyExchange() throws
        {
            guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(server.cipherSuite!) else {
                throw TLSError.error("No cipher suite")
            }
            
            switch cipherSuiteDescriptor.keyExchangeAlgorithm!
            {
            case .dhe:
                guard var dhParameters = server.configuration.dhParameters else {
                    throw TLSError.error("No DH parameters set in configuration")
                }
                
                let dhKeyExchange = DHKeyExchange(dhParameters: dhParameters)
                
                // use new public key for each key exchange
                dhParameters.Ys = dhKeyExchange.calculatePublicKey()
                
                server.keyExchange = .dhe(dhKeyExchange)
                
                let message = try TLSServerKeyExchange(keyExchangeParameters: .dhe(dhParameters), context: server)
                try server.sendHandshakeMessage(message)
                
            case .ecdhe:
                guard var ecdhParameters = server.configuration.ecdhParameters else {
                    throw TLSError.error("No ECDH parameters set in configuration")
                }
                
                let ecdhKeyExchange = ECDHKeyExchange(curve: ecdhParameters.curve)
                let Q = ecdhKeyExchange.calculatePublicKeyPoint()
                server.keyExchange = .ecdhe(ecdhKeyExchange)
                
                ecdhParameters.publicKey = Q
                let message = try TLSServerKeyExchange(keyExchangeParameters: .ecdhe(ecdhParameters), context:server)
                try server.sendHandshakeMessage(message)
                break
                
            default:
                throw TLSError.error("Cipher suite \(server.cipherSuite!) doesn't need server key exchange")
            }
        }

        func handleCertificate(_ certificate: TLSCertificateMessage) {
        }
        
        func handleClientHello(_ clientHello: TLSClientHello) throws {
            if !server.configuration.supports(clientHello.legacyVersion) {
                try server.abortHandshake()
            }
            
            // Secure Renegotiation
            let clientHelloContainsEmptyRenegotiationSCSV = clientHello.cipherSuites.contains(.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            let secureRenegotiationInfo = clientHello.extensions.filter({$0 is TLSSecureRenegotiationInfoExtension}).first as? TLSSecureRenegotiationInfoExtension
            
            if server.isInitialHandshake {
                // RFC 5746, Section 3.6
                if clientHelloContainsEmptyRenegotiationSCSV {
                    self.securityParameters.isUsingSecureRenegotiation = true
                }
                else if let secureRenegotiationInfo = secureRenegotiationInfo {
                    if secureRenegotiationInfo.renegotiatedConnection.count == 0 {
                        self.securityParameters.isUsingSecureRenegotiation = true
                    }
                    else {
                        // abort handshake if the renegotiationInfo isn't empty
                        try server.abortHandshake()
                    }
                }
                else {
                    self.securityParameters.isUsingSecureRenegotiation = false
                }
            }
            else if self.securityParameters.isUsingSecureRenegotiation {
                // Renegotiated handshake (RFC 5746, Section 3.7)
                if clientHelloContainsEmptyRenegotiationSCSV {
                    try server.abortHandshake()
                }
                else if let secureRenegotiationInfo = secureRenegotiationInfo {
                    if secureRenegotiationInfo.renegotiatedConnection.count == 0 {
                        try server.abortHandshake()
                    }
                    else {
                        if secureRenegotiationInfo.renegotiatedConnection != self.securityParameters.clientVerifyData {
                            try server.abortHandshake()
                        }
                        
                        self.isRenegotiatingSecurityParameters = true
                    }
                }
                else {
                    // abort if secureRenegotiationInfo is missing
                    try server.abortHandshake()
                }
            }
            else {
                log("Renegotiation initiated")
                
                self.securityParameters.isUsingSecureRenegotiation = false
            }
            
            
            if clientHello.legacyVersion.isKnownVersion {
                assert(server.configuration.supports(clientHello.legacyVersion))
                server.negotiatedProtocolVersion = clientHello.legacyVersion
            }
            else {
                server.negotiatedProtocolVersion = server.configuration.supportedVersions.first!
            }
            
            self.securityParameters.clientRandom = [UInt8](clientHello.random)
            
            server.cipherSuite = server.selectCipherSuite(clientHello.cipherSuites)
            
            if server.cipherSuite == nil {
                try server.sendAlert(.handshakeFailure, alertLevel: .fatal)
                throw TLSError.error("No shared cipher suites. Client supports:" + clientHello.cipherSuites.map({"\($0)"}).reduce("", {$0 + "\n" + $1}))
            }
            else {
                log("Selected cipher suite is \(server.cipherSuite!)")
            }
            
            log("client hello session ID: \(String(describing: clientHello.legacySessionID))")
            if let sessionID = clientHello.legacySessionID {
                if let session = self.serverContext.sessionCache[sessionID] {
                    log("Using cached session ID: \(sessionID.sessionID)")
                    server.currentSession = session
                    server.isReusingSession = true
                }
            }

        }
        
        func handleFinished(_ finished: TLSFinished) throws {
            if (self.verifyFinishedMessage(finished, isClient: true, saveForSecureRenegotiation: true)) {
                log("Server: Finished verified.")
                if self.isRenegotiatingSecurityParameters {
                    log("Server: Renegotiated security parameters successfully.")
                    self.isRenegotiatingSecurityParameters = false
                }
                
                if let sessionID = server.pendingSessionID {
                    let session = TLSSession(sessionID: sessionID, cipherSpec: server.cipherSuite!, masterSecret: self.securityParameters.masterSecret!)
                    self.serverContext.sessionCache[sessionID] = session
                    log("Save session \(session)")
                }
                
                server.handshakeMessages.append(finished)
            }
            else {
                log("Error: could not verify Finished message.")
                try server.sendAlert(.decryptError, alertLevel: .fatal)
            }
        }
        
        override func handleMessage(_ message: TLSMessage) throws {
            
            switch message.contentType {
            case .handshake:
                let handshake = message as! TLSHandshakeMessage
                switch handshake.handshakeType
                {
                case .clientKeyExchange:
                    try self.handleClientKeyExchange(handshake as! TLSClientKeyExchange)
                    
                default:
                    fatalError("handleMessage called with a handshake message that should be handled in a more specific method")
                }
                
            case .changeCipherSpec:
                try super.handleMessage(message)
                
            default:
                fatalError("handleMessage called with a message that should be handled at the TLSServer/TLSConnection level: \(message)")
            }

        }
        
        func handleClientKeyExchange(_ clientKeyExchange: TLSClientKeyExchange) throws {
            var preMasterSecret : [UInt8]
            
            switch (server.keyExchange, clientKeyExchange.keyExchange) {
                
            case (.dhe(var keyExchange), .dhe):
                keyExchange.peerPublicKey = clientKeyExchange.keyExchange.pfsKeyExchange?.publicKey
                
                if let sharedSecret = keyExchange.calculateSharedSecret() {
                    
                    preMasterSecret = sharedSecret
                }
                else {
                    fatalError("Client Key Exchange has no DHE public key")
                }

            case (.ecdhe(var keyExchange), .ecdhe):
                keyExchange.peerPublicKey = clientKeyExchange.keyExchange.pfsKeyExchange?.publicKey

                if let sharedSecret = keyExchange.calculateSharedSecret() {
                    
                    preMasterSecret = sharedSecret
                }
                else {
                    fatalError("Client Key Exchange has no ECDHE public key")
                }
                
            case (.rsa, .rsa):
                // RSA
                if let encryptedPreMasterSecret = clientKeyExchange.encryptedPreMasterSecret {
                    do {
                        let rsa = server.configuration.identity!.signer(with: self.connection.configuration.hashAlgorithm) as! RSA
                        preMasterSecret = try rsa.decrypt(encryptedPreMasterSecret)
                    } catch _ as RSA.Error {
                        throw TLSError.alert(alert: .decryptError, alertLevel: .fatal)
                    }
                }
                else {
                    fatalError("Client Key Exchange has no encrypted master secret")
                }
                
            default:
                // Is this even possible? We are deriving the TLSClientKeyEchange's keyExchange from the server's
                fatalError("Client And Server don't agree on key exchange")
            }
            
            self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret)
        }
        
        var connectionInfo: String {
            if let session = server.currentSession {
                return "Session ID: \(hex(session.sessionID.sessionID))"
            }
            
            return ""
        }
    }
}
