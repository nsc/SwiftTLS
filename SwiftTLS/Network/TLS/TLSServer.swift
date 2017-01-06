//
//  TLSServer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServer : TLSConnection
{
    // The saved sessions that the server can reuse when a client sends a sessionID
    // we know about from before
    var serverSessionCache: [TLSSessionID: TLSSession] = [:]
    
    override init(configuration: TLSConfiguration, dataProvider : TLSDataProvider? = nil)
    {
        super.init(configuration: configuration, dataProvider: dataProvider)
        
        self.stateMachine = ServerStateMachine(server: self)

        if let identity = self.configuration.identity {
            // we are currently only supporting RSA
            if let rsa = identity.rsa {
                self.signer = rsa
            }
        }
    }
    
    func acceptConnection() throws
    {
        reset()
        
        try self.receiveNextTLSMessage()
        
        try self.didConnect()
        
        self.handshakeMessages = []
    }
    
    override func handleHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        let handshakeType = message.handshakeType
        
        switch (handshakeType)
        {
        case .clientHello:
            let clientHello = (message as! TLSClientHello)
            
            if !self.configuration.supports(version: clientHello.legacyVersion) {
                try abortHandshake()
            }
            
            // Secure Renegotiation
            let clientHelloContainsEmptyRenegotiationSCSV = clientHello.cipherSuites.contains(.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            let secureRenegotiationInfo = clientHello.extensions.filter({$0 is TLSSecureRenegotiationInfoExtension}).first as? TLSSecureRenegotiationInfoExtension
            
            print("ClientHello extensions: \(clientHello.extensions)")
            if self.isInitialHandshake {
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
                        try abortHandshake()
                    }
                }
                else {
                    self.securityParameters.isUsingSecureRenegotiation = false
                }
            }
            else if self.securityParameters.isUsingSecureRenegotiation {
                // Renegotiated handshake (RFC 5746, Section 3.7)
                if clientHelloContainsEmptyRenegotiationSCSV {
                    try abortHandshake()
                }
                else if let secureRenegotiationInfo = secureRenegotiationInfo {
                    if secureRenegotiationInfo.renegotiatedConnection.count == 0 {
                        try abortHandshake()
                    }
                    else {
                        if secureRenegotiationInfo.renegotiatedConnection != self.securityParameters.clientVerifyData {
                            try abortHandshake()
                        }
                        
                        self.isRenegotiatingSecurityParameters = true
                    }
                }
                else {
                    // abort if secureRenegotiationInfo is missing
                    try abortHandshake()
                }
            }
            else {
                print("Renegotiation initiated")
                
                self.securityParameters.isUsingSecureRenegotiation = false
            }
            
            
            if clientHello.legacyVersion.isKnownVersion {
                assert(self.configuration.supports(version: clientHello.legacyVersion))
                self.negotiatedProtocolVersion = clientHello.legacyVersion
            }
            else {
                self.negotiatedProtocolVersion = self.configuration.supportedVersions.first!
            }
            
            self.securityParameters.clientRandom = DataBuffer(clientHello.random).buffer
            
            self.cipherSuite = self.selectCipherSuite(clientHello.cipherSuites)
            
            if self.cipherSuite == nil {
                try self.sendAlert(.handshakeFailure, alertLevel: .fatal)
                throw TLSError.error("No shared cipher suites. Client supports:" + clientHello.cipherSuites.map({"\($0)"}).reduce("", {$0 + "\n" + $1}))
            }
            else {
                print("Selected cipher suite is \(self.cipherSuite!)")
            }
            
            print("client hello session ID: \(clientHello.legacySessionID)")
            if let sessionID = clientHello.legacySessionID {
                if let session = self.serverSessionCache[sessionID] {
                    print("Using cached session ID: \(sessionID.sessionID)")
                    self.currentSession = session
                    self.isReusingSession = true
                }
            }
            
        case .clientKeyExchange:
            let clientKeyExchange = message as! TLSClientKeyExchange
            var preMasterSecret : [UInt8]
            
            
            switch self.keyExchange {
                
            case .dhe(let dhKeyExchange):
                // Diffie-Hellman
                if let diffieHellmanPublicKey = clientKeyExchange.diffieHellmanPublicKey {
                    dhKeyExchange.peerPublicKey = diffieHellmanPublicKey
                    preMasterSecret = dhKeyExchange.calculateSharedSecret()!.asBigEndianData()
                }
                else {
                    fatalError("Client Key Exchange has no DH public key")
                }
                
            case .ecdhe(let ecdhKeyExchange):
                if let ecdhPublicKey = clientKeyExchange.ecdhPublicKey {
                    ecdhKeyExchange.peerPublicKey = ecdhPublicKey
                    preMasterSecret = ecdhKeyExchange.calculateSharedSecret()!.asBigEndianData()
                }
                else {
                    fatalError("Client Key Exchange has no ECDH public key")
                }
                
            case .rsa:
                // RSA
                if let encryptedPreMasterSecret = clientKeyExchange.encryptedPreMasterSecret {
                    preMasterSecret = self.configuration.identity!.rsa!.decrypt(encryptedPreMasterSecret)
                }
                else {
                    fatalError("Client Key Exchange has no encrypted master secret")
                }
            }
            
            self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret)
            
        case .finished:
            if (self.verifyFinishedMessage(message as! TLSFinished, isClient: true, saveForSecureRenegotiation: true)) {
                print("Server: Finished verified.")
                if self.isRenegotiatingSecurityParameters {
                    print("Server: Renegotiated security parameters successfully.")
                    self.isRenegotiatingSecurityParameters = false
                }
                
                if let sessionID = self.pendingSessionID {
                    let session = TLSSession(sessionID: sessionID, cipherSpec: self.cipherSuite!, masterSecret: self.securityParameters.masterSecret!)
                    serverSessionCache[sessionID] = session
                    print("Save session \(session)")
                }
                
                self.handshakeMessages.append(message)
            }
            else {
                print("Error: could not verify Finished message.")
                try sendAlert(.decryptionFailed, alertLevel: .fatal)
            }
            
        default:
            throw TLSError.error("Unsupported handshake \(handshakeType.rawValue)")
        }
        
        try self.stateMachine?.didReceiveHandshakeMessage(message)
    }

    func sendServerHello() throws
    {
        var sessionID: TLSSessionID
        if let session = currentSession {
            sessionID = session.sessionID
        }
        else {
            // create new session id
            repeat {
                sessionID = TLSSessionID.new()
            } while serverSessionCache[sessionID] != nil
            
            self.pendingSessionID = sessionID
        }
        
        let serverHelloRandom = Random()
        let serverHello = TLSServerHello(
            serverVersion: self.negotiatedProtocolVersion,
            random: serverHelloRandom,
            sessionID: sessionID,
            cipherSuite: self.cipherSuite!,
            compressionMethod: .null)
        
        if self.securityParameters.isUsingSecureRenegotiation {
            if self.isInitialHandshake {
                serverHello.extensions.append(TLSSecureRenegotiationInfoExtension())
            }
            else {
                let renegotiationInfo = self.securityParameters.clientVerifyData + self.securityParameters.serverVerifyData
                serverHello.extensions.append(TLSSecureRenegotiationInfoExtension(renegotiatedConnection: renegotiationInfo))
            }
        }
        
        print("ServerHello extensions = \(serverHello.extensions)")
        
        self.securityParameters.serverRandom = DataBuffer(serverHelloRandom).buffer
        if let session = currentSession {
            setPendingSecurityParametersForCipherSuite(session.cipherSpec)
        }
        
        self.isInitialHandshake = false
        
        try self.sendHandshakeMessage(serverHello)
        
        usleep(300000)
    }
    
    func sendServerHelloDone() throws
    {
        try self.sendHandshakeMessage(TLSServerHelloDone())
    }
    
    func sendServerKeyExchange() throws
    {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(self.cipherSuite!) else {
            throw TLSError.error("No cipher suite")
        }
        
        switch cipherSuiteDescriptor.keyExchangeAlgorithm
        {
        case .dhe:
            guard var dhParameters = self.configuration.dhParameters else {
                throw TLSError.error("No DH parameters set in configuration")
            }
            
            let dhKeyExchange = DHKeyExchange(dhParameters: dhParameters)
            
            // use new public key for each key exchange
            dhParameters.Ys = dhKeyExchange.calculatePublicKey()
            
            self.keyExchange = .dhe(dhKeyExchange)
            
            let message = TLSServerKeyExchange(dhParameters: dhParameters, context: self)
            try self.sendHandshakeMessage(message)
            
        case .ecdhe:
            guard var ecdhParameters = self.configuration.ecdhParameters else {
                throw TLSError.error("No ECDH parameters set in configuration")
            }
            
            let ecdhKeyExchange = ECDHKeyExchange(curve: ecdhParameters.curve)
            let Q = ecdhKeyExchange.calculatePublicKey()
            self.keyExchange = .ecdhe(ecdhKeyExchange)
            
            ecdhParameters.publicKey = Q
            let message = TLSServerKeyExchange(ecdhParameters: ecdhParameters, context:self)
            try self.sendHandshakeMessage(message)
            break
            
        default:
            throw TLSError.error("Cipher suite \(self.cipherSuite) doesn't need server key exchange")
        }
    }

}
