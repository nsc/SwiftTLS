//
//  TLS1_3.ServerProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ServerProtocol : BaseProtocol, TLSServerProtocol
    {
        weak var server: TLSServer! {
            return self.connection as! TLSServer
        }
        
        init(server: TLSServer)
        {
            super.init(connection: server)
        }

        func sendServerHello() throws {
            let serverHelloRandom = Random()
            let serverHello = TLSServerHello(
                serverVersion: server.negotiatedProtocolVersion!,
                random: serverHelloRandom,
                sessionID: nil,
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
            
            // Normally we would use sendHandshakeMessage here, which would implicitly add the message to
            // the handShakeMessages and cal didSendHandshakeMessage on the stateMachine.
            // But since that would immediately trigger the sending of EncryptedExtensions, we have no chance
            // to establish the encryption keys inbetween.
            // So until we come can come up with a different architecture to do this, we are doing the three
            // steps here by hand, intermixed with establishing the encryption keys
            try server.sendMessage(serverHello)
            server.handshakeMessages.append(serverHello)
            
            deriveEarlySecret()
            deriveHandshakeSecret(with: keyExchange)
            
            try server.stateMachine?.didSendHandshakeMessage(serverHello)
        }
        
        func sendEncryptedExtensions() throws {
            let encryptedExtensions = TLSEncryptedExtensions(extensions: [])
            try server.sendHandshakeMessage(encryptedExtensions)
        }
        
        func handleClientHello(_ clientHello: TLSClientHello) throws {

            guard let negotiatedProtocolVersion = selectVersion(for: clientHello) else {
                try server.abortHandshake()
                return
            }
            
            if negotiatedProtocolVersion < .v1_3 {
                // fallback to lesser version
                server.setupServer(with: self.server.configuration, version: negotiatedProtocolVersion)
                
                try server.serverProtocolHandler.handleClientHello(clientHello)
                
                return
            }
            
            server.negotiatedProtocolVersion = negotiatedProtocolVersion
            
            print("ClientHello extensions: \(clientHello.extensions)")
            
            guard let cipherSuite = server.selectCipherSuite(clientHello.cipherSuites) else {
                try server.sendAlert(.handshakeFailure, alertLevel: .fatal)
                throw TLSError.error("No shared cipher suites. Client supports:" + clientHello.cipherSuites.map({"\($0)"}).reduce("", {$0 + "\n" + $1}))
            }
            
            print("Selected cipher suite is \(cipherSuite)")
            
            guard let keyShare = selectKeyShare(clientHello: clientHello) else {
                throw TLSError.error("Could not agree on a keyShare")
            }
            
            server.cipherSuite = cipherSuite
            server.clientKeyShare = keyShare
        }
        
        override func sendFinished() throws
        {
            let verifyData = self.finishedData(forClient: connection.isClient)
            
            try self.connection.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
            
            // The secret contains all the handshake messages up to Server Finished, so the server has to derive
            // it after sending its Finished
            deriveApplicationTrafficSecrets()
        }

        func handleFinished(_ finished: TLSFinished) throws {
            // Activate the application traffic secret after Client Finished
            self.recordLayer.changeTrafficSecrets(clientTrafficSecret: self.handshakeState.clientTrafficSecret!,
                                                  serverTrafficSecret: self.handshakeState.serverTrafficSecret!)
        }
        
        func handleCertificate(_ certificate: TLSCertificateMessage) {
        }
        
        func handleMessage(_ message: TLSMessage) throws {
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
        
        func selectKeyShare(clientHello: TLSClientHello) -> KeyShareEntry?
        {
            guard let keyShareExtension = clientHello.extensions.first(where: { $0 is TLSKeyShareExtension }) as? TLSKeyShareExtension else {
                return nil
            }
            
            if case .clientHello(let keyShares) = keyShareExtension.keyShare {
                for keyShare in keyShares {
                    if server.configuration.supportedGroups.contains(keyShare.namedGroup) {
                        return keyShare
                    }
                }
            }
            else {
                return nil
            }

            return nil
        }
    }
}
