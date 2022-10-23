//
//  TLSConnection.swift
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

extension Socket : TLSDataProvider {}

public class TLSConnection
{
    init(configuration: TLSConfiguration, context: TLSContext? = nil, socket: SocketProtocol)
    {
        self.socket = socket
        self.configuration = configuration
        
        self.context = context
        
        self.negotiatedProtocolVersion = configuration.supportedVersions.first!
        self.handshakeMessages = []
        self.keyExchange = .rsa
        self.isReusingSession = false
        
        switch self.negotiatedProtocolVersion! {
        case TLSProtocolVersion.v1_0, TLSProtocolVersion.v1_1, TLSProtocolVersion.v1_2:
            self.recordLayer = TLS1_2.RecordLayer(connection: self, dataProvider: (socket as! TLSDataProvider))
            
        case TLSProtocolVersion.v1_3:
            self.recordLayer = TLS1_3.RecordLayer(connection: self, dataProvider: (socket as! TLSDataProvider))
            
        default:
            fatalError("No such version \(self.negotiatedProtocolVersion!)")
            break
        }
    }
    
    public var peerAddress: IPAddress? {
        (socket as? Socket)?.peerName
    }

    var socket: SocketProtocol
    var protocolHandler: TLSProtocol!

    public var configuration: TLSConfiguration
    public var context: TLSContext!
    
    var negotiatedProtocolVersion: TLSProtocolVersion? {
        didSet {
            if let version = negotiatedProtocolVersion {
                self.recordLayer.protocolVersion = version
            }
        }
    }
    
    public var connectionInfo: String {
        return """
        Connection from \(peerAddress!)
        TLS Version: \(self.negotiatedProtocolVersion!)
        Cipher: \(self.cipherSuite!)
        \(self.protocolHandler.connectionInfo)
        """ + (self.earlyData != nil ? "Early data was sent\n" : "")
    }
    
    var serverNames: [String]?
    
    public var cipherSuite: CipherSuite? {
        didSet {
            if  let cipherSuite = cipherSuite,
                let cipherSuiteDescription = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite) {
                
                self.hashAlgorithm = cipherSuiteDescription.hashAlgorithm
            }
        }
    }
    
    var currentMessage: TLSMessage?
    
    var stateMachine: TLSConnectionStateMachine?
    
    var peerCertificates: [X509.Certificate]?
    
    var handshakeMessages: [TLSHandshakeMessage]
    
    var transcriptHash: [UInt8] {
        return transcriptHash(droppingLast: 0)
    }
    
    private func transcriptHash(droppingLast numberOfDroppedBytes: Int) -> [UInt8] {
        var handshakeData: [UInt8] = []
        for message in self.handshakeMessages {
            if self.negotiatedProtocolVersion == .v1_3 {
                
                // Check for special construct when a HelloRetryRequest is included
                // see section 4.4.1 "The Transcript Hash" in RFC 8446
                if message is TLSServerHello && (message as! TLSServerHello).isHelloRetryRequest {
                    let hashLength = self.hashAlgorithm.hashLength
                    let hashValue = self.hashAlgorithm.hashFunction(handshakeData)
                    
                    handshakeData = [TLSHandshakeType.messageHash.rawValue, 0, 0, UInt8(hashLength)] + hashValue
                }
            }
            
            handshakeData.append(contentsOf: message.messageData(with: self))
        }
        
        return self.hashAlgorithm.hashFunction([UInt8](handshakeData.dropLast(numberOfDroppedBytes)))
    }
    
    func transcriptHashWithTruncatedClientHello(droppingLast numberOfDroppedBytes: Int) -> [UInt8] {
        return transcriptHash(droppingLast: numberOfDroppedBytes)
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
    
    public var earlyData: [UInt8]? = nil
    public var earlyDataWasAccepted: Bool = false
    
    private var connectionEstablishedCompletionBlock : ((_ error : TLSError?) -> ())?

    func reset() {
        
        currentSession = nil
        pendingSessionID = nil
        
        isInitialHandshake = true
        isReusingSession = false

        negotiatedProtocolVersion = configuration.supportedVersions.first!
        handshakeMessages = []
        keyExchange = .rsa
        
        switch negotiatedProtocolVersion! {
        case TLSProtocolVersion.v1_0, TLSProtocolVersion.v1_1, TLSProtocolVersion.v1_2:
            recordLayer = TLS1_2.RecordLayer(connection: self, dataProvider: recordLayer.dataProvider!)
        
        case TLSProtocolVersion.v1_3:
            recordLayer = TLS1_3.RecordLayer(connection: self, dataProvider: recordLayer.dataProvider!)
        
        default:
            fatalError("No such version \(negotiatedProtocolVersion!)")
            break
        }

        stateMachine?.reset()
    }
    
    func didConnect() throws
    {
        try stateMachine?.didConnect()
    }

    func didRenegotiate()
    {
        log("Renegotiated security parameters successfully.")
    }

    
    func sendApplicationData(_ data : [UInt8]) async throws
    {
        try await recordLayer.sendData(contentType: .applicationData, data: data)
    }
    
    func sendMessage(_ message : TLSMessage) async throws
    {
        try await recordLayer.sendMessage(message)
        currentMessage = message

        switch message.contentType
        {
        case .handshake:
            break

        default:
            try stateMachine?.didSendMessage(message)
        }
    }
    
    func sendAlert(_ alert : TLSAlert, alertLevel : TLSAlertLevel) async throws
    {
        let alertMessage = TLSAlertMessage(alert: alert, alertLevel: alertLevel)
        try await sendMessage(alertMessage)
    }
    
    func abortHandshake(with alert: TLSAlert = .handshakeFailure) async throws -> Never
    {
        try await self.sendAlert(alert, alertLevel: .fatal)
        throw TLSError.alert(alert, alertLevel: .fatal)
    }
    
    func sendHandshakeMessage(_ message : TLSHandshakeMessage, appendToTranscript: Bool = true) async throws
    {
        try await self.sendMessage(message)
        
        if appendToTranscript {
            self.handshakeMessages.append(message)
        }
        
        try await stateMachine?.didSendHandshakeMessage(message)
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
    
    func _didReceiveMessage(_ message : TLSMessage) async throws
    {
        switch (message.type)
        {
        case .changeCipherSpec:
            try stateMachine?.didReceiveChangeCipherSpec()
            _ = try await receiveNextTLSMessage()
            
            break
            
        case .handshake:
            let handshakeMessage = message as! TLSHandshakeMessage
            if stateMachine == nil || stateMachine!.shouldContinueHandshake(with: handshakeMessage) {
                try await _didReceiveHandshakeMessage(handshakeMessage)
            }
            else {
                throw TLSError.error("Handshake aborted")
            }

        case .alert:
            let alert = message as! TLSAlertMessage
            stateMachine?.didReceiveAlert(alert)
            if alert.alertLevel == .fatal {
                throw TLSError.alert(alert.alert, alertLevel: alert.alertLevel)
            }
            
            break
            
        case .applicationData:
            break
        }
    }

    func _didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) async throws
    {
        let handshakeType = message.handshakeType

        self.didReceiveHandshakeMessage(message)
        
        switch handshakeType {
        case .finished, .newSessionTicket, .certificateVerify:
            // don't add the incoming message to handshakeMessages.
            // We need to verify it's data against the handshake messages before it.
            break
            
        default:
            self.handshakeMessages.append(message)
        }
                
        if handshakeType != .finished && handshakeType != .newSessionTicket {
//            try await receiveNextTLSMessage()
        }
    }
        
    internal func sign(_ data : [UInt8]) throws -> [UInt8]
    {
        guard let signer = self.signer else {
            fatalError("Unsupported signature algorithm \(String(describing: self.configuration.signatureAlgorithm))")
        }
        
        return try signer.sign(data: data)
    }
    
    func receiveNextTLSMessage() async throws -> TLSMessage {
        let message = try await recordLayer.readMessage()
        
        self.currentMessage = message
        
        try await self._didReceiveMessage(message)
        
        return message
    }
    
    func readTLSMessage() async throws -> TLSMessage
    {
        while true {
            let message = try await receiveNextTLSMessage()
            
            if message.contentType == .applicationData {
                return message
            }
            
            self.currentMessage = message

            try await _didReceiveMessage(message)
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
}

extension TLSConnection : SocketProtocol {
    public var isReadyToRead: Bool {
        socket.isReadyToRead
    }
    
    public func close() async {
        do {
            try await sendAlert(.closeNotify, alertLevel: .warning)
        }
        catch
        {
        }
        
        // When the send is done, close the underlying socket
        // We might want to have an option to wait for the peer to send *its* closeNotify if it wants to
        await socket.close()
    }
    
    public func read(count: Int) async throws -> [UInt8]
    {
        let message = try await readTLSMessage()
        switch message.type
        {
        case .applicationData:
            let applicationData = (message as! TLSApplicationData).applicationData
            
            if applicationData.count == 0 {
                return try await read(count: count)
            }
            else {
                return applicationData
            }
            
        case .alert(let level, let alert):
            log("Alert: \(level) \(alert)")
            return []
            
        default:
            throw TLSError.error("Error: unhandled message \(message)")
        }
    }
    
    func readData(count: Int) async throws -> [UInt8]
    {
        try await socket.read(count: count)
    }
    
    func writeData(_ data: [UInt8]) async throws
    {
        try await socket.write(data)
    }
    
    public func write(_ data: [UInt8]) async throws
    {
        try await sendApplicationData(data)
    }
    
    public func write(_ data: Data) async throws {
        try await write([UInt8](data))
    }
}
