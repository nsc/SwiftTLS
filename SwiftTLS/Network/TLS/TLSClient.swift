//
//  TLSClient.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSClient : TLSConnection
{
    // The client session cache is indexed by hostname and port concatenated to
    // a string "\(hostname):\(port)"
    var clientSessionCache: [String : TLSSession] = [:]
    
    override init(configuration: TLSConfiguration, dataProvider : TLSDataProvider? = nil)
    {
        super.init(configuration: configuration, dataProvider: dataProvider)
        
        self.stateMachine = ClientStateMachine(client: self)
    }
    
    func startConnection() throws
    {
        reset()
        
        try self.sendClientHello()
        try self.receiveNextTLSMessage()
        
        try self.didConnect()
        
        self.handshakeMessages = []
    }
    
    override func handleHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        let handshakeType = message.handshakeType
        
        switch (handshakeType)
        {
        case .serverHello:
            let serverHello = message as! TLSServerHello
            let version = serverHello.version
            print("Server wants to speak \(version)")
            
            guard version.isKnownVersion &&
                self.configuration.supports(version: version) else
            {
                try abortHandshake()
                return
            }
            
            self.recordLayer?.protocolVersion = version
            self.negotiatedProtocolVersion = version
            
            self.cipherSuite = serverHello.cipherSuite
            self.securityParameters.serverRandom = DataBuffer(serverHello.random).buffer
            
            print("ServerHello extensions = \(serverHello.extensions)")
            
            if let secureRenegotiationInfo = serverHello.extensions.filter({$0 is TLSSecureRenegotiationInfoExtension}).first as? TLSSecureRenegotiationInfoExtension {
                print("Client setting secure renegotiation")
                self.securityParameters.isUsingSecureRenegotiation = true
                
                if self.isInitialHandshake {
                    if secureRenegotiationInfo.renegotiatedConnection.count != 0 {
                        try abortHandshake()
                    }
                }
                else {
                    if secureRenegotiationInfo.renegotiatedConnection != self.securityParameters.clientVerifyData + self.securityParameters.serverVerifyData {
                        try abortHandshake()
                    }
                }
            }
            else {
                if !isInitialHandshake && self.securityParameters.isUsingSecureRenegotiation {
                    // When we are using secure renegotiation and the server hello doesn't include
                    // the extension, we need to abort the handshake
                    try abortHandshake()
                }
                self.securityParameters.isUsingSecureRenegotiation = false
            }
            
            if let sessionID = serverHello.sessionID {
                if  let pendingSessionID = self.pendingSessionID,
                    sessionID == pendingSessionID {
                    let hostname = hostNames!.first!
                    let session = clientSessionCache[hostname]!
                    if session.sessionID == sessionID {
                        self.currentSession = session
                        self.isReusingSession = true
                        setPendingSecurityParametersForCipherSuite(session.cipherSpec)
                    }
                    else {
                        fatalError("Session lost. This should not be possible.")
                    }
                }
                else {
                    self.pendingSessionID = sessionID
                }
                print("Session ID: \(sessionID.sessionID)")
            }
            
            if currentSession == nil && !serverHello.cipherSuite.needsServerKeyExchange()
            {
                let preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: self.configuration.supportedVersions.first!)).buffer
                self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret, cipherSuite: serverHello.cipherSuite)
            }
            
        case .certificate:
            let certificateMessage = message as! TLSCertificateMessage
            self.serverCertificates = certificateMessage.certificates
            self.serverKey = serverCertificates!.first!.rsa
            
        case .serverKeyExchange:
            let keyExchangeMessage = message as! TLSServerKeyExchange
            
            switch keyExchangeMessage.parameters {
                
            case .dhe(let diffieHellmanParameters):
                
                let p = diffieHellmanParameters.p
                let g = diffieHellmanParameters.g
                let Ys = diffieHellmanParameters.Ys
                
                let dhKeyExchange = DHKeyExchange(primeModulus: p, generator: g)
                dhKeyExchange.peerPublicKey = Ys
                
                self.keyExchange = .dhe(dhKeyExchange)
                
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
                self.keyExchange = .ecdhe(ecdhKeyExchange)
            }
            
            // verify signature
            if let certificate = self.serverCertificates?.first {
                if let rsa = certificate.publicKeySigner {
                    let signedData = keyExchangeMessage.signedParameters
                    var data = self.securityParameters.clientRandom!
                    data += self.securityParameters.serverRandom!
                    data += keyExchangeMessage.parametersData
                    
                    if !rsa.verify(signature: signedData.signature, data: data) {
                        throw TLSError.error("Signature error on server key exchange")
                    }
                }
            }
            
        case .serverHelloDone:
            break
            
        case .finished:
            if (self.verifyFinishedMessage(message as! TLSFinished, isClient: false, saveForSecureRenegotiation: true)) {
                print("Client: Finished verified.")
                if self.isRenegotiatingSecurityParameters {
                    print("Client: Renegotiated security parameters successfully.")
                    self.isRenegotiatingSecurityParameters = false
                }
                
                if currentSession != nil {
                    self.handshakeMessages.append(message)
                    
                    try self.stateMachine?.didReceiveHandshakeMessage(message)
                    
                    try self.sendChangeCipherSpec()
                    
                    return
                }
                else if let sessionID = self.pendingSessionID {
                    if let hostname = hostNames?.first {
                        let session = TLSSession(sessionID: sessionID, cipherSpec: self.cipherSuite!, masterSecret: self.securityParameters.masterSecret!)
                        clientSessionCache[hostname] = session
                        print("Save session for \(hostname)")
                    }
                }
                
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

    func sendClientHello() throws
    {
        // reset current pending session ID
        self.pendingSessionID = nil
        self.currentSession = nil
        self.isReusingSession = false
        
        self.handshakeMessages = []
        
        var cipherSuites = self.configuration.cipherSuites
        if self.isInitialHandshake {
            // Only the initial handshake may contain the empty renegotiation info signalling cipher suite
            if !cipherSuites.contains(.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                cipherSuites.append(.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            }
        }
        else {
            self.isRenegotiatingSecurityParameters = self.securityParameters.isUsingSecureRenegotiation
        }
        
        //        if !self.isRenegotiatingSecurityParameters {
        if let hostname = self.hostNames?.first {
            self.pendingSessionID = clientSessionCache[hostname]?.sessionID
        }
        //        }
        
        let clientHelloRandom = Random()
        let clientHello = TLSClientHello(
            configuration: self.configuration,
            random: clientHelloRandom,
            sessionID: pendingSessionID,
            cipherSuites: cipherSuites,
            compressionMethods: [.null])
        
        if self.hostNames != nil {
            clientHello.extensions.append(TLSServerNameExtension(serverNames: self.hostNames!))
        }
        
        //        print("initial handshake = \(self.isInitialHandshake), secure renegotiation = \(self.securityParameters.isUsingSecureRenegotiation)")
        if self.isRenegotiatingSecurityParameters {
            clientHello.extensions.append(TLSSecureRenegotiationInfoExtension(renegotiatedConnection: self.securityParameters.clientVerifyData))
            print("ClientHello extensions = \(clientHello.extensions)")
        }
        
        if self.configuration.cipherSuites.contains(where: { if let descriptor = TLSCipherSuiteDescriptorForCipherSuite($0) { return descriptor.keyExchangeAlgorithm == .ecdhe} else { return false } }) {
            clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: [.secp256r1, .secp521r1]))
            clientHello.extensions.append(TLSEllipticCurvePointFormatsExtension(ellipticCurvePointFormats: [.uncompressed]))
        }
        
        self.isInitialHandshake = false
        
        self.securityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
        try self.sendHandshakeMessage(clientHello)
    }

    func sendClientKeyExchange() throws
    {
        switch self.keyExchange {
        case .dhe(let diffieHellmanKeyExchange):
            // Diffie-Hellman
            let publicKey = diffieHellmanKeyExchange.calculatePublicKey()
            let sharedSecret = diffieHellmanKeyExchange.calculateSharedSecret()!
            
            self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret.asBigEndianData())
            
            let message = TLSClientKeyExchange(diffieHellmanPublicKey: publicKey)
            try self.sendHandshakeMessage(message)
            
        case .ecdhe(let ecdhKeyExchange):
            let Q = ecdhKeyExchange.calculatePublicKey()
            let sharedSecret = ecdhKeyExchange.calculateSharedSecret()!
            
            self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret.asBigEndianData())
            
            let message = TLSClientKeyExchange(ecdhPublicKey: Q)
            try self.sendHandshakeMessage(message)
            
        case .rsa:
            if let rsa = self.serverKey {
                // RSA
                let message = TLSClientKeyExchange(preMasterSecret: self.preMasterSecret!, rsa: rsa)
                try self.sendHandshakeMessage(message)
            }
        }
    }
    
    func renegotiate() throws
    {
        try sendClientHello()
        _ = try self.readTLSMessage()
        
        self.didRenegotiate()
    }
    
}
