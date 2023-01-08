//
//  TLSClientProtocol1_2.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_2 {
    class ClientProtocol : BaseProtocol, TLSClientProtocol
    {        
        weak var client: TLSClient! {
            return (self.connection as! TLSClient)
        }
        
        var serverKey: Signing?
        
        var clientContext: TLSClientContext {
            return self.connection.context as! TLSClientContext
        }
        
        init(client: TLSClient)
        {
            super.init(connection: client)
        }
        
        func connect() async throws {
            try await sendClientHello()
            try await receive(TLSServerHello.self)
            
            if client.isReusingSession {
                // abbreviated handshake
                try await receive(TLSChangeCipherSpec.self)
                try await receive(TLSFinished.self)
                try await sendChangeCipherSpec()
                try await sendFinished()
            }
            else {
                // full handshake
                try await receive(TLSCertificateMessage.self)
                
                if client.cipherSuite!.needsServerKeyExchange() {
                    try await receive(TLSServerKeyExchange.self)
                }
                try await receive(TLSServerHelloDone.self)

                try await sendClientKeyExchange()
                try await sendChangeCipherSpec()
                try await sendFinished()
                
                try await receive(TLSChangeCipherSpec.self)

                try await receive(TLSFinished.self)
            }
        }
        
        func sendClientHello() async throws
        {
            var cipherSuites = client.configuration.cipherSuites
            if client.isInitialHandshake {
                // Only the initial handshake may contain the empty renegotiation info signalling cipher suite
                if !cipherSuites.contains(.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                    cipherSuites.append(.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
                }
            }
            else {
                self.isRenegotiatingSecurityParameters = self.securityParameters.isUsingSecureRenegotiation
            }
            
            //        if !self.isRenegotiatingSecurityParameters {
            if let hostname = client.serverNames?.first {
                client.pendingSessionID = self.clientContext.sessionCache[hostname]?.sessionID
            }
            //        }
            
            let clientHelloRandom = Random()
            let clientHello = TLSClientHello(
                configuration: client.configuration,
                random: clientHelloRandom,
                sessionID: client.pendingSessionID,
                cipherSuites: cipherSuites,
                compressionMethods: [.null])
            
            if client.serverNames != nil {
                clientHello.extensions.append(TLSServerNameExtension(serverNames: client.serverNames!))
            }
            
            //        log("initial handshake = \(self.isInitialHandshake), secure renegotiation = \(self.securityParameters.isUsingSecureRenegotiation)")
            if self.isRenegotiatingSecurityParameters {
                clientHello.extensions.append(TLSSecureRenegotiationInfoExtension(renegotiatedConnection: self.securityParameters.clientVerifyData))
            }
            
            if client.configuration.cipherSuites.contains(where: { if let descriptor = TLSCipherSuiteDescriptorForCipherSuite($0) { return descriptor.keyExchangeAlgorithm == .ecdhe} else { return false } }) {
                clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: [.secp256r1, .secp384r1, .secp521r1]))
                clientHello.extensions.append(TLSEllipticCurvePointFormatsExtension(ellipticCurvePointFormats: [.uncompressed]))
            }
            
            client.isInitialHandshake = false
            
            self.securityParameters.clientRandom = [UInt8](clientHelloRandom)
            
            try await client.sendHandshakeMessage(clientHello)
        }
        
        func handle(_ serverHello: TLSServerHello) async throws
        {
            let version = serverHello.legacyVersion
            log("Server wants to speak \(version)")
            
            guard version.isKnownVersion &&
                client.configuration.supports(version) else
            {
                try await client.abortHandshake()
            }
            
            client.recordLayer?.protocolVersion = version
            client.negotiatedProtocolVersion = version
            
            client.cipherSuite = serverHello.cipherSuite
            self.securityParameters.serverRandom = [UInt8](serverHello.random)
                        
            if let secureRenegotiationInfo = serverHello.extensions.filter({$0 is TLSSecureRenegotiationInfoExtension}).first as? TLSSecureRenegotiationInfoExtension {
                log("Client setting secure renegotiation")
                self.securityParameters.isUsingSecureRenegotiation = true
                
                if client.isInitialHandshake {
                    if secureRenegotiationInfo.renegotiatedConnection.count != 0 {
                        try await client.abortHandshake()
                    }
                }
                else {
                    if secureRenegotiationInfo.renegotiatedConnection != self.securityParameters.clientVerifyData + self.securityParameters.serverVerifyData {
                        try await client.abortHandshake()
                    }
                }
            }
            else {
                if !client.isInitialHandshake && self.securityParameters.isUsingSecureRenegotiation {
                    // When we are using secure renegotiation and the server hello doesn't include
                    // the extension, we need to abort the handshake
                    try await client.abortHandshake()
                }
                self.securityParameters.isUsingSecureRenegotiation = false
            }
            
            if let sessionID = serverHello.legacySessionID {
                if  let pendingSessionID = client.pendingSessionID,
                    sessionID == pendingSessionID {
                    let serverName = client.serverNames!.first!
                    let session = self.clientContext.sessionCache[serverName]!
                    if session.sessionID == sessionID {
                        client.currentSession = session
                        client.isReusingSession = true
                        self.setPendingSecurityParametersForCipherSuite(session.cipherSpec)
                    }
                    else {
                        fatalError("Session lost. This should not be possible.")
                    }
                }
                else {
                    client.pendingSessionID = sessionID
                }
                log("Session ID: \(sessionID.sessionID)")
            }
            
            if client.currentSession == nil && !serverHello.cipherSuite.needsServerKeyExchange()
            {
                // The PreMasterSecret includes the version that we announced in our ClientHello.
                // If the server only supports TLS 1.2 or less, it was only looking at the legacy version and
                // doesn't know about TLS 1.3. So even though our configuration might support 1.3, we have to
                // use the legay version here.
                let legacyVersion = client.configuration.supportedVersions.filter({$0 <= TLSProtocolVersion.v1_2}).first!
                let preMasterSecret = [UInt8](PreMasterSecret(clientVersion: legacyVersion))
                self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret, cipherSuite: serverHello.cipherSuite)
            }
        }
        
        func sendClientKeyExchange() async throws
        {
            switch connection.keyExchange {
            case .dhe(let keyExchange): //, .ecdhe(let keyExchange):
                keyExchange.createKeyPair()
                
                let sharedSecret = keyExchange.calculateSharedSecret()!
                
                self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret)
                
                let message = TLSClientKeyExchange(keyExchange: connection.keyExchange)
                try await connection.sendHandshakeMessage(message)
                
            case .ecdhe(let keyExchange):
                keyExchange.createKeyPair()
                
                let sharedSecret = keyExchange.calculateSharedSecret()!
                
                self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret)
                
                let message = TLSClientKeyExchange(keyExchange: connection.keyExchange)
                try await connection.sendHandshakeMessage(message)

            case .rsa:
                if let rsa = self.serverKey as? RSA {
                    // RSA
                    let message = TLSClientKeyExchange(preMasterSecret: self.preMasterSecret!, rsa: rsa)
                    try await connection.sendHandshakeMessage(message)
                }
            }
        }
        
        func renegotiate() async throws
        {
            try await sendClientHello()
            _ = try await connection.readTLSMessage()
            
            connection.didRenegotiate()
        }

        func handle(_ finished: TLSFinished) throws {
            
            if (verifyFinishedMessage(finished, isClient: false, saveForSecureRenegotiation: true)) {
                log("Client: Finished verified.")
                if isRenegotiatingSecurityParameters {
                    log("Client: Renegotiated security parameters successfully.")
                    isRenegotiatingSecurityParameters = false
                }
                
                if client.currentSession != nil {
                    client.handshakeMessages.append(finished)
                    
//                    try client.stateMachine?.didReceiveHandshakeMessage(finished)
                    
//                    try self.sendChangeCipherSpec()
                }
                else if let sessionID = client.pendingSessionID {
                    if let serverName = client.serverNames?.first {
                        let session = TLSSession(sessionID: sessionID, cipherSpec: client.cipherSuite!, masterSecret: self.securityParameters.masterSecret!)
                        clientContext.sessionCache[serverName] = session
                        log("Save session for \(serverName)")
                    }
                }
                
            }
            else {
                log("Error: could not verify Finished message.")
                throw TLSError.alert(.decryptError, alertLevel: .fatal)
            }
        }
        
        func handle(_ certificate: TLSCertificateMessage) {
            let certificates = certificate.certificates
            client.peerCertificates = certificates
            serverKey = certificates.first!.publicKeySigner
        }
        
        override func handleMessage(_ message: TLSMessage) async throws {
            switch message.contentType {
            case .handshake:
                let handshake = message as! TLSHandshakeMessage
                switch handshake.handshakeType
                {
                case .serverHello:
                    try await self.handle(handshake as! TLSServerHello)
                    
                case .serverKeyExchange:
                    try self.handle(handshake as! TLSServerKeyExchange)
                    
                case .serverHelloDone:
                    break
                    
                case .certificate:
                    self.handle(handshake as! TLSCertificateMessage)

                case .finished:
                    try self.handle(handshake as! TLSFinished)

                default:
                    fatalError("handleMessage called with a handshake message that should be handled in a more specific method")
                }
                
            case .changeCipherSpec:
                try await super.handleMessage(message)
                break
                
            default:
                fatalError("handleMessage called with a message that should be handled at the TLSClient/TLSConnection level: \(message)")
            }
        }
        
        func handle(_ serverKeyExchange: TLSServerKeyExchange) throws {
            
            switch serverKeyExchange.parameters {
                
            case .dhe(let diffieHellmanParameters):
                
                let p = diffieHellmanParameters.p
                let g = diffieHellmanParameters.g
                
                let dhKeyExchange = DHKeyExchange(primeModulus: p, generator: g)
                dhKeyExchange.peerPublicKey = diffieHellmanParameters.publicKey
                
                client.keyExchange = .dhe(dhKeyExchange)
                
            case .ecdhe(let ecdhParameters):
                switch ecdhParameters.curveType
                {
                case .namedCurve(let namedCurve):
                    guard
                        let curve = EllipticCurve.named(namedCurve)
                        else {
                            throw TLSError.error("Unsupported curve \(namedCurve)")
                    }
                    log("Using curve \(namedCurve)")

                    let ecdhKeyExchange = ECDHKeyExchange(curve: curve)
                    ecdhKeyExchange.peerPublicKeyPoint = ecdhParameters.publicKey
                    client.keyExchange = .ecdhe(ecdhKeyExchange)

                default:
                    throw TLSError.error("Unsupported curve type \(ecdhParameters.curveType)")
                }
            }
            
            // verify signature
            if let certificate = client.peerCertificates?.first {
                if var signer = certificate.publicKeySigner {
                    let signedData = serverKeyExchange.signedParameters
                    var data = self.securityParameters.clientRandom!
                    data += self.securityParameters.serverRandom!
                    data += serverKeyExchange.parametersData
                    
                    if  let algorithm = signedData.signatureAlgorithm,
                        let hashAlgorithm = signedData.hashAlgorithm,
                        let signatureAlgorithm = X509.SignatureAlgorithm(signatureAlgorithm: algorithm, hashAlgorithm: hashAlgorithm) {
                        
                        signer.algorithm = signatureAlgorithm
                    }
                    
                    if try !signer.verify(signature: signedData.signature, data: data) {
                        throw TLSError.error("Signature error on server key exchange")
                    }
                }
            }
            
        }
        
        var connectionInfo: String {
            return ""
        }
    }
}
