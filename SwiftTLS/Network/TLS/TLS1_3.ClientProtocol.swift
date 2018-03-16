//
//  TLS1_3.ClientProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ClientProtocol : BaseProtocol, TLSClientProtocol {
        weak var client: TLSClient! {
            return self.connection as! TLSClient
        }
        
        // We need to remember this in case the server wants to fallback to
        // a TLS version < 1.3. In that case we need to switch to a different
        // protocol handler and hand it the client hello random
        var clientHelloRandom: Random?
        
        init(client: TLSClient)
        {
            super.init(connection: client)
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
            
            if client.hostNames != nil {
                clientHello.extensions.append(TLSServerNameExtension(serverNames: client.hostNames!))
            }
            
            guard client.configuration.supportedGroups.count > 0 else {
                throw TLSError.error("TLS 1.3 configuration is missing supported key shares.")
            }
            
            let groups = client.configuration.supportedGroups
            
            clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: groups))
            
            var keyShareEntries : [KeyShareEntry] = []
            for group in groups {
                
                if let curve = EllipticCurve.named(group) {
                    let keyExchange = ECDHKeyExchange(curve: curve)
                    let Q = keyExchange.calculatePublicKeyPoint()
                    
                    let data = DataBuffer(Q).buffer
                    keyShareEntries.append(KeyShareEntry(namedGroup: group, keyExchange: data))
                    
                    self.client.keyExchangesAnnouncedToServer[group] = .ecdhe(keyExchange)
                }
            }
            
            clientHello.extensions.append(TLSSignatureAlgorithmExtension(signatureAlgorithms: [.rsa_pkcs1_sha256, .rsa_pss_sha256]))
            clientHello.extensions.append(TLSKeyShareExtension(keyShare: .clientHello(clientShares: keyShareEntries)))
                            
            try client.sendHandshakeMessage(clientHello)
        }
        
        func handleServerHello(_ serverHello: TLSServerHello) throws {
            guard serverHello.version == .v1_3 else {
        
                // If the server does not support TLS 1.3, fall back to lower version
                // if the configuration supports it
        
                if !client.configuration.supports(serverHello.version) {
                    try client.abortHandshake()
                    return
                }
                
                switch serverHello.version {
                case TLSProtocolVersion.v1_2:
                    client.setupClient(with: .v1_2)
                    let protocolHandler = client.protocolHandler as! TLS1_2.ClientProtocol
                    protocolHandler.securityParameters.clientRandom = DataBuffer(self.clientHelloRandom!).buffer

                    try client.clientProtocolHandler.handleServerHello(serverHello)
                    
                default:
                    try client.abortHandshake()
                }
                
                return
            }
            
            client.recordLayer?.protocolVersion = .v1_3
            client.negotiatedProtocolVersion    = .v1_3
            
            client.cipherSuite = serverHello.cipherSuite

            for serverExtension in serverHello.extensions {
                
                switch serverExtension.extensionType {
                case .keyShare:
                    if case .serverHello(let keyShare) = (serverExtension as! TLSKeyShareExtension).keyShare {
                        let group = keyShare.namedGroup
                        let peerPublicKey = keyShare.keyExchange
                        guard var keyExchange = client.keyExchangesAnnouncedToServer[group]?.pfsKeyExchange else {
                            throw TLSError.alert(alert: .illegalParameter, alertLevel: .fatal)
                        }

                        keyExchange.peerPublicKey = peerPublicKey
                        
                        deriveEarlySecret()
                        deriveHandshakeSecret(with: keyExchange)
                    }
                    else {
                        // FIXME: Is this the right error to throw here? What does the RFC say about it?
                        throw TLSError.alert(alert: .decodeError, alertLevel: .fatal)
                    }
                    
                case .supportedVersions:
                    break
                    
                default:
                    print("Unhandled extension \(serverExtension)")
                }
            }
            
            if self.handshakeState.earlySecret == nil || self.handshakeState.handshakeSecret == nil {
                throw TLSError.alert(alert: .handshakeFailure, alertLevel: .fatal)
            }
        }
        
        override func sendFinished() throws
        {
            let verifyData = self.finishedData(forClient: connection.isClient)
            
            // The secret contains all the handshake messages up to Server Finished, so the client has to derive
            // it before sending its Finished
            deriveApplicationTrafficSecrets()
        
            try self.connection.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
            
            if !self.connection.isClient {
                // The server has to derive its secret after sending its Finished
                deriveApplicationTrafficSecrets()
            }
            
            self.recordLayer.changeTrafficSecrets(clientTrafficSecret: self.handshakeState.clientTrafficSecret!,
                                                  serverTrafficSecret: self.handshakeState.serverTrafficSecret!)
        }

        func handleMessage(_ message: TLSMessage) throws {
            
        }
        
        func handleCertificate(_ certificate: TLSCertificateMessage) {
            
        }
        
        func handleFinished(_ finished: TLSFinished) throws {
            // Verify finished data
            let finishedData = self.finishedData(forClient: false)
            if finishedData != finished.verifyData {
                print("Error: could not verify Finished message.")
                try client.sendAlert(.decryptError, alertLevel: .fatal)
            }
            
            client.handshakeMessages.append(finished)
        }
        
    }
}
