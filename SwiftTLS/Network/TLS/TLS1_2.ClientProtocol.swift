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
            return self.connection as! TLSClient
        }
        
        var serverKey: RSA?
        
        init(client: TLSClient)
        {
            super.init(connection: client)
        }
        
        func sendClientHello() throws
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
            if let hostname = client.hostNames?.first {
                client.pendingSessionID = client.clientContext.sessionCache[hostname]?.sessionID
            }
            //        }
            
            let clientHelloRandom = Random()
            let clientHello = TLSClientHello(
                configuration: client.configuration,
                random: clientHelloRandom,
                sessionID: client.pendingSessionID,
                cipherSuites: cipherSuites,
                compressionMethods: [.null])
            
            if client.hostNames != nil {
                clientHello.extensions.append(TLSServerNameExtension(serverNames: client.hostNames!))
            }
            
            //        print("initial handshake = \(self.isInitialHandshake), secure renegotiation = \(self.securityParameters.isUsingSecureRenegotiation)")
            if self.isRenegotiatingSecurityParameters {
                clientHello.extensions.append(TLSSecureRenegotiationInfoExtension(renegotiatedConnection: self.securityParameters.clientVerifyData))
                print("ClientHello extensions = \(clientHello.extensions)")
            }
            
            if client.configuration.cipherSuites.contains(where: { if let descriptor = TLSCipherSuiteDescriptorForCipherSuite($0) { return descriptor.keyExchangeAlgorithm == .ecdhe} else { return false } }) {
                clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: [.secp256r1, .secp521r1]))
                clientHello.extensions.append(TLSEllipticCurvePointFormatsExtension(ellipticCurvePointFormats: [.uncompressed]))
            }
            
            client.isInitialHandshake = false
            
            self.securityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
            
            try client.sendHandshakeMessage(clientHello)
        }
        
        func handleServerHello(_ serverHello: TLSServerHello) throws
        {
            let version = serverHello.version
            print("Server wants to speak \(version)")
            
            guard version.isKnownVersion &&
                client.configuration.supports(version) else
            {
                try client.abortHandshake()
                return
            }
            
            client.recordLayer?.protocolVersion = version
            client.negotiatedProtocolVersion = version
            
            client.cipherSuite = serverHello.cipherSuite
            self.securityParameters.serverRandom = DataBuffer(serverHello.random).buffer
            
            print("ServerHello extensions = \(serverHello.extensions)")
            
            if let secureRenegotiationInfo = serverHello.extensions.filter({$0 is TLSSecureRenegotiationInfoExtension}).first as? TLSSecureRenegotiationInfoExtension {
                print("Client setting secure renegotiation")
                self.securityParameters.isUsingSecureRenegotiation = true
                
                if client.isInitialHandshake {
                    if secureRenegotiationInfo.renegotiatedConnection.count != 0 {
                        try client.abortHandshake()
                    }
                }
                else {
                    if secureRenegotiationInfo.renegotiatedConnection != self.securityParameters.clientVerifyData + self.securityParameters.serverVerifyData {
                        try client.abortHandshake()
                    }
                }
            }
            else {
                if !client.isInitialHandshake && self.securityParameters.isUsingSecureRenegotiation {
                    // When we are using secure renegotiation and the server hello doesn't include
                    // the extension, we need to abort the handshake
                    try client.abortHandshake()
                }
                self.securityParameters.isUsingSecureRenegotiation = false
            }
            
            if let sessionID = serverHello.sessionID {
                if  let pendingSessionID = client.pendingSessionID,
                    sessionID == pendingSessionID {
                    let hostname = client.hostNames!.first!
                    let session = client.clientContext.sessionCache[hostname]!
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
                print("Session ID: \(sessionID.sessionID)")
            }
            
            if client.currentSession == nil && !serverHello.cipherSuite.needsServerKeyExchange()
            {
                // The PreMasterSecret includes the version that we announced in our ClientHello.
                // If the server only supports TLS 1.2 or less, it was only looking at the legacy version and
                // doesn't know about TLS 1.3. So even though our configuration might support 1.3, we have to
                // use the legay version here.
                let legacyVersion = client.configuration.supportedVersions.filter({$0 <= TLSProtocolVersion.v1_2}).first!
                let preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: legacyVersion)).buffer
                self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret, cipherSuite: serverHello.cipherSuite)
            }
        }
        
        func sendClientKeyExchange() throws
        {
            switch connection.keyExchange {
            case .dhe(let keyExchange): //, .ecdhe(let keyExchange):
                keyExchange.createKeyPair()
                
                let sharedSecret = keyExchange.calculateSharedSecret()!
                
                self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret)
                
                let message = TLSClientKeyExchange(keyExchange: connection.keyExchange)
                try connection.sendHandshakeMessage(message)
                
            case .ecdhe(let keyExchange):
                keyExchange.createKeyPair()
                
                let sharedSecret = keyExchange.calculateSharedSecret()!
                
                self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret)
                
                let message = TLSClientKeyExchange(keyExchange: connection.keyExchange)
                try connection.sendHandshakeMessage(message)

            case .rsa:
                if let rsa = self.serverKey {
                    // RSA
                    let message = TLSClientKeyExchange(preMasterSecret: self.preMasterSecret!, rsa: rsa)
                    try connection.sendHandshakeMessage(message)
                }
            }
        }
        
        func renegotiate() throws
        {
            try sendClientHello()
            _ = try connection.readTLSMessage()
            
            connection.didRenegotiate()
        }

        func handleFinished(_ finished: TLSFinished) throws {
            
            if (self.verifyFinishedMessage(finished, isClient: false, saveForSecureRenegotiation: true)) {
                print("Client: Finished verified.")
                if self.isRenegotiatingSecurityParameters {
                    print("Client: Renegotiated security parameters successfully.")
                    self.isRenegotiatingSecurityParameters = false
                }
                
                if client.currentSession != nil {
                    client.handshakeMessages.append(finished)
                    
                    try client.stateMachine?.didReceiveHandshakeMessage(finished)
                    
                    try self.sendChangeCipherSpec()
                    
                    return
                }
                else if let sessionID = client.pendingSessionID {
                    if let hostname = client.hostNames?.first {
                        let session = TLSSession(sessionID: sessionID, cipherSpec: client.cipherSuite!, masterSecret: self.securityParameters.masterSecret!)
                        client.clientContext.sessionCache[hostname] = session
                        print("Save session for \(hostname)")
                    }
                }
                
            }
            else {
                print("Error: could not verify Finished message.")
                try client.sendAlert(.decryptError, alertLevel: .fatal)
            }
            
        }
        
        func handleCertificate(_ certificate: TLSCertificateMessage) {
            let certificates = certificate.certificates
            client.serverCertificates = certificates
            self.serverKey = certificates.first!.rsa
        }
        
        override func handleMessage(_ message: TLSMessage) throws {
            
            switch message.contentType {
            case .handshake:
                let handshake = message as! TLSHandshakeMessage
                switch handshake.handshakeType
                {
                case .serverKeyExchange:
                    try self.handleServerKeyExchange(handshake as! TLSServerKeyExchange)
                    
                case .serverHelloDone:
                    break
                    
                default:
                    fatalError("handleMessage called with a handshake message that should be handled in a more specific method")
                }
                
            case .changeCipherSpec:
                try super.handleMessage(message)
                break
                
            default:
                fatalError("handleMessage called with a message that should be handled at the TLSClient/TLSConnection level: \(message)")
            }
        }
        
        func handleServerKeyExchange(_ serverKeyExchange: TLSServerKeyExchange) throws {
            
            switch serverKeyExchange.parameters {
                
            case .dhe(let diffieHellmanParameters):
                
                let p = diffieHellmanParameters.p
                let g = diffieHellmanParameters.g
                let Ys = diffieHellmanParameters.Ys
                
                let dhKeyExchange = DHKeyExchange(primeModulus: p, generator: g)
                dhKeyExchange.Ys = Ys
                
                client.keyExchange = .dhe(dhKeyExchange)
                
            case .ecdhe(let ecdhParameters):
                if ecdhParameters.curveType != .namedCurve {
                    throw TLSError.error("Unsupported curve type \(ecdhParameters.curveType)")
                }
                
                guard
                    let namedCurve = ecdhParameters.namedCurve,
                    let curve = EllipticCurve.named(namedCurve)
                    else {
                        throw TLSError.error("Unsupported curve \(ecdhParameters.namedCurve)")
                }
                print("Using curve \(namedCurve)")
                
                let ecdhKeyExchange = ECDHKeyExchange(curve: curve)
                ecdhKeyExchange.peerPublicKeyPoint = ecdhParameters.publicKey
                client.keyExchange = .ecdhe(ecdhKeyExchange)
            }
            
            // verify signature
            if let certificate = client.serverCertificates?.first {
                if let rsa = certificate.publicKeySigner {
                    let signedData = serverKeyExchange.signedParameters
                    var data = self.securityParameters.clientRandom!
                    data += self.securityParameters.serverRandom!
                    data += serverKeyExchange.parametersData
                    
                    if !rsa.verify(signature: signedData.signature, data: data) {
                        throw TLSError.error("Signature error on server key exchange")
                    }
                }
            }
            
        }
    }
}
