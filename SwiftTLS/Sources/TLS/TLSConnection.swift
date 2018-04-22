//
//  TLSConnection.swift
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

let tls1_3_prefix = [UInt8]("tls13 ".utf8)

public class TLSConnection
{
    internal var protocolHandler: TLSProtocol!

    public var configuration: TLSConfiguration
    public var context: TLSContext!
    
    var negotiatedProtocolVersion: TLSProtocolVersion? {
        didSet {
            if let version = negotiatedProtocolVersion {
                self.recordLayer.protocolVersion = version
            }
        }
    }
    
    var serverNames: [String]?
    
    var cipherSuite: CipherSuite? {
        didSet {
            if  let cipherSuite = cipherSuite,
                let cipherSuiteDescription = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite) {
                
                self.hashAlgorithm = cipherSuiteDescription.hashAlgorithm
            }
        }
    }
    var stateMachine: TLSConnectionStateMachine?
    
    var serverCertificates: [X509.Certificate]?
    
    var handshakeMessages: [TLSHandshakeMessage]
    
    var transcriptHash: [UInt8] {
        var handshakeData: [UInt8] = []
        for message in self.handshakeMessages {
            if let version = self.negotiatedProtocolVersion,
                version == .v1_3 {
                
                // Check for special construct when a HelloRetryRequest is included
                // see section "The Transcript Hash" in RFC TLS 1.3
                if message is TLSServerHello && (message as! TLSServerHello).isHelloRetryRequest {
                    let hashLength = self.hashAlgorithm.hashLength
                    let hashValue = self.hashAlgorithm.hashFunction(handshakeData)
                    
                    handshakeData = [TLSHandshakeType.messageHash.rawValue, 0, 0, UInt8(hashLength)] + hashValue
                }
            }
            
            handshakeData.append(contentsOf: message.messageData(with: self))
        }
        
        return self.hashAlgorithm.hashFunction(handshakeData)
    }
    
    var handshakeMessageData: [UInt8] {
        var handshakeData: [UInt8] = []
        for message in self.handshakeMessages {
            handshakeData.append(contentsOf: message.messageData(with: self))
        }
        
        return handshakeData
    }
    
    var isClient: Bool {
        return self is TLSClient
    }
    
    var recordLayer: TLSRecordLayer!
    
    var keyExchange: KeyExchange
    
    var signer: Signing?

    // The current session, if there is one already
    var currentSession: TLSSession?
    
    // The session ID that will be used once the handshake is finished and the session
    // can be set up. This is used in TLS < 1.3 only
    var pendingSessionID: TLSSessionID?
    
    var isReusingSession: Bool
    
    var isInitialHandshake: Bool = true
    
    var hashAlgorithm: HashAlgorithm = .sha256
    
    var hmac: HMACFunction {
        return self.hashAlgorithm.macAlgorithm.hmacFunction
    }
    
    // TLS 1.3
    var preSharedKey: [UInt8]?
    
    var earlyData: [UInt8]? = nil
    var earlyDataWasSent: Bool = false
    
    private var connectionEstablishedCompletionBlock : ((_ error : TLSError?) -> ())?

    init(configuration: TLSConfiguration, context: TLSContext? = nil, dataProvider : TLSDataProvider? = nil)
    {
        self.configuration = configuration
        
        self.context = context
        
        self.negotiatedProtocolVersion = configuration.supportedVersions.first!
        self.handshakeMessages = []
        self.keyExchange = .rsa
        self.isReusingSession = false
        
        if let dataProvider = dataProvider {
            switch self.negotiatedProtocolVersion! {
            case TLSProtocolVersion.v1_0, TLSProtocolVersion.v1_1, TLSProtocolVersion.v1_2:
                self.recordLayer = TLS1_2.RecordLayer(connection: self, dataProvider: dataProvider)
            
            case TLSProtocolVersion.v1_3:
                self.recordLayer = TLS1_3.RecordLayer(connection: self, dataProvider: dataProvider)
            
            default:
                fatalError("No such version \(self.negotiatedProtocolVersion!)")
                break
            }
        }
    }
    
    func reset() {
        self.currentSession = nil
        self.pendingSessionID = nil
        
        self.isInitialHandshake = true
        
        self.negotiatedProtocolVersion = configuration.supportedVersions.first!
        self.handshakeMessages = []
        self.keyExchange = .rsa
        
        switch self.negotiatedProtocolVersion! {
        case TLSProtocolVersion.v1_0, TLSProtocolVersion.v1_1, TLSProtocolVersion.v1_2:
            self.recordLayer = TLS1_2.RecordLayer(connection: self, dataProvider: self.recordLayer.dataProvider!)
        
        case TLSProtocolVersion.v1_3:
            self.recordLayer = TLS1_3.RecordLayer(connection: self, dataProvider: self.recordLayer.dataProvider!)
        
        default:
            fatalError("No such version \(self.negotiatedProtocolVersion!)")
            break
        }

        self.stateMachine?.reset()
    }
    
    func didConnect() throws
    {
        try self.stateMachine?.didConnect()
    }

    func didRenegotiate()
    {
        log("Renegotiated security parameters successfully.")
    }

    
    func sendApplicationData(_ data : [UInt8]) throws
    {
        try self.recordLayer.sendData(contentType: .applicationData, data: data)
    }
    
    func sendMessage(_ message : TLSMessage) throws
    {
        try self.recordLayer.sendMessage(message)
        
        switch message.contentType
        {
        case .handshake:
            break

        default:
            try self.stateMachine?.didSendMessage(message)
        }
    }
    
    func sendAlert(_ alert : TLSAlert, alertLevel : TLSAlertLevel) throws
    {
        let alertMessage = TLSAlertMessage(alert: alert, alertLevel: alertLevel)
        try self.sendMessage(alertMessage)
    }
    
    func abortHandshake(with alert: TLSAlert = .handshakeFailure) throws -> Never
    {
        try self.sendAlert(alert, alertLevel: .fatal)
        throw TLSError.alert(alert: alert, alertLevel: .fatal)
    }
    
    func sendHandshakeMessage(_ message : TLSHandshakeMessage, appendToTranscript: Bool = true) throws
    {
        try self.sendMessage(message)
        
        if appendToTranscript {
            self.handshakeMessages.append(message)
        }
        
        try self.stateMachine?.didSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage)
    {
        if let clientHello = message as? TLSClientHello {
            log("Supported Cipher Suites:")
            for cipherSuite in clientHello.cipherSuites {
                log("\(cipherSuite)")
            }
        }
    }
    
    func _didReceiveMessage(_ message : TLSMessage) throws
    {
        switch (message.type)
        {
        case .changeCipherSpec:
            try self.protocolHandler.handleMessage(message)
            try self.stateMachine?.didReceiveChangeCipherSpec()
            try self.receiveNextTLSMessage()
            
            break
            
        case .handshake:
            let handshakeMessage = message as! TLSHandshakeMessage
            if self.stateMachine == nil || self.stateMachine!.shouldContinueHandshake(with: handshakeMessage) {
                try self._didReceiveHandshakeMessage(handshakeMessage)
            }

        case .alert:
            let alert = message as! TLSAlertMessage
            self.stateMachine?.didReceiveAlert(alert)
            if alert.alertLevel == .fatal {
                throw TLSError.alert(alert: alert.alert, alertLevel: alert.alertLevel)
            }
            
            break
            
        case .applicationData:
            break
        }
    }

    func handleHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
    }
    

    func _didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        let handshakeType = message.handshakeType

        self.didReceiveHandshakeMessage(message)
        
        if handshakeType != .finished && handshakeType != .newSessionTicket {
            // don't add the incoming Finished message to handshakeMessages.
            // We need to verify it's data against the handshake messages before it.
            self.handshakeMessages.append(message)
        }
        
        try self.handleHandshakeMessage(message)
        
        if handshakeType != .finished && handshakeType != .newSessionTicket {
            try self.receiveNextTLSMessage()
        }
    }
        
    internal func sign(_ data : [UInt8]) throws -> [UInt8]
    {
        guard let signer = self.signer else {
            fatalError("Unsupported signature algorithm \(self.configuration.signatureAlgorithm)")
        }
        
        return try signer.sign(data: data)
    }
    
    func receiveNextTLSMessage() throws
    {
        let message = try self.recordLayer.readMessage()

        try self._didReceiveMessage(message)
    }

    func readTLSMessage() throws -> TLSMessage
    {
        while true {
            let message = try self.recordLayer.readMessage()
            
            if message.contentType == .applicationData {
                return message
            }
            
            try self._didReceiveMessage(message)
        }
    }
    
    func selectCipherSuite(_ cipherSuites : [CipherSuite]) -> CipherSuite?
    {
        guard let version = self.negotiatedProtocolVersion else {
            return nil
        }
        
        for cipherSuite in self.configuration.cipherSuites.filter({TLSCipherSuiteDescriptorForCipherSuite($0)?.supportedProtocolVersions.contains(version) ?? false}) {
            if cipherSuites.contains(cipherSuite) {
                return cipherSuite
            }
        }
        
        return nil
    }
    
//    func deriveSharedSecret() throws -> [UInt8] {
//        switch self.keyExchange {
//        case .dhe(let diffieHellmanKeyExchange):
//            // Diffie-Hellman
//            let publicKey = diffieHellmanKeyExchange.calculatePublicKey()
//            let sharedSecret = diffieHellmanKeyExchange.calculateSharedSecret()!
//            
//            return sharedSecret.asBigEndianData()
//            
//        case .ecdhe(let ecdhKeyExchange):
//            let Q = ecdhKeyExchange.calculatePublicKey()
//            let sharedSecret = ecdhKeyExchange.calculateSharedSecret()!
//            
//            return sharedSecret.asBigEndianData()
//            
//        case .rsa: break
//        }
//    }
}
