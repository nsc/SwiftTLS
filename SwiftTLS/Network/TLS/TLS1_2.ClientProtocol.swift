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
                client.isRenegotiatingSecurityParameters = client.securityParameters.isUsingSecureRenegotiation
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
            if client.isRenegotiatingSecurityParameters {
                clientHello.extensions.append(TLSSecureRenegotiationInfoExtension(renegotiatedConnection: client.securityParameters.clientVerifyData))
                print("ClientHello extensions = \(clientHello.extensions)")
            }
            
            if client.configuration.cipherSuites.contains(where: { if let descriptor = TLSCipherSuiteDescriptorForCipherSuite($0) { return descriptor.keyExchangeAlgorithm == .ecdhe} else { return false } }) {
                clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: [.secp256r1, .secp521r1]))
                clientHello.extensions.append(TLSEllipticCurvePointFormatsExtension(ellipticCurvePointFormats: [.uncompressed]))
            }
            
            client.isInitialHandshake = false
            
            client.securityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
            
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
            client.securityParameters.serverRandom = DataBuffer(serverHello.random).buffer
            
            print("ServerHello extensions = \(serverHello.extensions)")
            
            if let secureRenegotiationInfo = serverHello.extensions.filter({$0 is TLSSecureRenegotiationInfoExtension}).first as? TLSSecureRenegotiationInfoExtension {
                print("Client setting secure renegotiation")
                client.securityParameters.isUsingSecureRenegotiation = true
                
                if client.isInitialHandshake {
                    if secureRenegotiationInfo.renegotiatedConnection.count != 0 {
                        try client.abortHandshake()
                    }
                }
                else {
                    if secureRenegotiationInfo.renegotiatedConnection != client.securityParameters.clientVerifyData + client.securityParameters.serverVerifyData {
                        try client.abortHandshake()
                    }
                }
            }
            else {
                if !client.isInitialHandshake && client.securityParameters.isUsingSecureRenegotiation {
                    // When we are using secure renegotiation and the server hello doesn't include
                    // the extension, we need to abort the handshake
                    try client.abortHandshake()
                }
                client.securityParameters.isUsingSecureRenegotiation = false
            }
            
            if let sessionID = serverHello.sessionID {
                if  let pendingSessionID = client.pendingSessionID,
                    sessionID == pendingSessionID {
                    let hostname = client.hostNames!.first!
                    let session = client.clientContext.sessionCache[hostname]!
                    if session.sessionID == sessionID {
                        client.currentSession = session
                        client.isReusingSession = true
                        client.setPendingSecurityParametersForCipherSuite(session.cipherSpec)
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
                let preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: client.configuration.supportedVersions.first!)).buffer
                client.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret, cipherSuite: serverHello.cipherSuite)
            }
        }
        
        func handleFinished(_ finished: TLSFinished) throws {
            
            if (client.verifyFinishedMessage(finished, isClient: false, saveForSecureRenegotiation: true)) {
                print("Client: Finished verified.")
                if client.isRenegotiatingSecurityParameters {
                    print("Client: Renegotiated security parameters successfully.")
                    client.isRenegotiatingSecurityParameters = false
                }
                
                if client.currentSession != nil {
                    client.handshakeMessages.append(finished)
                    
                    try client.stateMachine?.didReceiveHandshakeMessage(finished)
                    
                    try self.sendChangeCipherSpec()
                    
                    return
                }
                else if let sessionID = client.pendingSessionID {
                    if let hostname = client.hostNames?.first {
                        let session = TLSSession(sessionID: sessionID, cipherSpec: client.cipherSuite!, masterSecret: client.securityParameters.masterSecret!)
                        client.clientContext.sessionCache[hostname] = session
                        print("Save session for \(hostname)")
                    }
                }
                
            }
            else {
                print("Error: could not verify Finished message.")
                try client.sendAlert(.decryptionFailed, alertLevel: .fatal)
            }
            
        }
        
        func handleCertificate(_ certificate: TLSCertificateMessage) {
            let certificates = certificate.certificates
            client.serverCertificates = certificates
            client.serverKey = certificates.first!.rsa
        }
        
        func handleMessage(_ message: TLSMessage) throws {
            
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
                dhKeyExchange.peerPublicKey = Ys
                
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
                ecdhKeyExchange.peerPublicKey = ecdhParameters.publicKey
                client.keyExchange = .ecdhe(ecdhKeyExchange)
            }
            
            // verify signature
            if let certificate = client.serverCertificates?.first {
                if let rsa = certificate.publicKeySigner {
                    let signedData = serverKeyExchange.signedParameters
                    var data = client.securityParameters.clientRandom!
                    data += client.securityParameters.serverRandom!
                    data += serverKeyExchange.parametersData
                    
                    if !rsa.verify(signature: signedData.signature, data: data) {
                        throw TLSError.error("Signature error on server key exchange")
                    }
                }
            }
            
        }
    }
}
