//
//  TLSClient.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

public class TLSClient : TLSConnection
{
    internal var clientProtocolHandler: TLSClientProtocol! {
        get {
            return (self.protocolHandler as! TLSClientProtocol)
        }
    }

    public init(configuration: TLSConfiguration, context: TLSContext? = nil, stateMachine: TLSClientStateMachine? = nil)
    {
        super.init(configuration: configuration, context: context, socket: TCPSocket())

        if !(context is TLSClientContext) {
            self.context = configuration.createClientContext()
        }
        
        var protocolVersion = self.configuration.supportedVersions.first
        if protocolVersion == nil {
            protocolVersion = .v1_2
        }
        
        setupClient(with: protocolVersion!, stateMachine: stateMachine)
    }
    
    func startConnection(withEarlyData earlyData: [UInt8]? = nil) throws
    {
        reset()
        
        self.earlyData = earlyData
        
        do {
            try self.sendClientHello()
            while stateMachine?.state != .connected {
                try self.receiveNextTLSMessage()
            }
        } catch TLSError.alert(alert: let alert, alertLevel: let alertLevel) {
            if alertLevel == .fatal {
                try abortHandshake(with: alert)
            }
            
            throw TLSError.alert(alert: alert, alertLevel: alertLevel)
        }
                
        self.handshakeMessages = []
    }
    
    override func handleHandshakeMessage(_ message : TLSHandshakeMessage) throws -> Bool
    {
        guard try !super.handleHandshakeMessage(message) else {
            return true
        }

        let handshakeType = message.handshakeType
        
        switch (handshakeType)
        {
        case .serverHello:
            let serverHello = message as! TLSServerHello
            try self.clientProtocolHandler.handleServerHello(serverHello)

        case .certificate:
            let certificateMessage = message as! TLSCertificateMessage
            self.protocolHandler.handleCertificate(certificateMessage)
            
        case .finished:
            try self.protocolHandler.handleFinished(message as! TLSFinished)
            
        default:
            try self.protocolHandler.handleMessage(message)
        }
        
        try self.stateMachine?.didReceiveHandshakeMessage(message)
        
        return true
    }

    func sendClientHello() throws
    {
        // reset current pending session ID
        self.pendingSessionID = nil
        self.currentSession = nil
        self.isReusingSession = false
        
        self.handshakeMessages = []
        
        try self.clientProtocolHandler.sendClientHello()
    }
    
    func setupClient(with version: TLSProtocolVersion, stateMachine: TLSClientStateMachine? = nil)
    {
        let state = self.stateMachine?.state
        
        switch version {
        case TLSProtocolVersion.v1_2:
            self.protocolHandler    = TLS1_2.ClientProtocol(client: self)
            self.stateMachine       = stateMachine ?? TLS1_2.ClientStateMachine(client: self)
            self.recordLayer        = TLS1_2.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)

        case TLSProtocolVersion.v1_3:
            self.protocolHandler    = TLS1_3.ClientProtocol(client: self)
            self.stateMachine       = stateMachine ?? TLS1_3.ClientStateMachine(client: self)
            self.recordLayer        = TLS1_3.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)

        default:
            fatalError("Unsupported protocol \(version)")
        }
        
        if let state = state {
            self.stateMachine!.state = state
        }
    }
}

extension TLSClient : ClientSocketProtocol
{
    var clientSocket: ClientSocketProtocol {
        return (self.socket as! ClientSocketProtocol)
    }
    
    public func connect(_ address: IPAddress, withEarlyData earlyData: Data) throws
    {
        try self.clientSocket.connect(address)
        try self.startConnection(withEarlyData: [UInt8](earlyData))
    }
    
    // Connect with early data.
    public func connect(hostname: String, port: UInt16 = 443, withEarlyData earlyData: Data) throws
    {
        self.earlyData = [UInt8](earlyData)
        
        try connect(hostname: hostname, port: port)
    }
    
    public func connect(hostname: String, port: UInt16 = 443) throws
    {
        if let address = IPv4Address.addressWithString(hostname, port: port) {
            var hostNameAndPort = hostname
            if port != 443 {
                hostNameAndPort = "\(hostname):\(port)"
            }
            self.serverNames = [hostNameAndPort]
            
            try connect(address)
        }
        else {
            throw TLSError.error("Error: Could not resolve host \(hostname)")
        }
        
    }
    
    public enum EarlyDataState {
        case none
        case sent
        case accepted
        case rejected
    }
    
    public var earlyDataState: EarlyDataState {
        guard let state = (clientProtocolHandler as? TLS1_3.ClientProtocol)?.clientHandshakeState.earlyDataState else {
            return .none
        }
        
        switch state {
        case .none: return .none
        case .sent: return .sent
        case .accepted: return .accepted
        case .rejected: return .rejected
        }
    }
    
    // TODO: add connect method that takes a domain name rather than an IP
    // so we can check the server certificate against that name
    public func connect(_ address: IPAddress) throws
    {
        try self.clientSocket.connect(address)
        try self.startConnection(withEarlyData: self.earlyData)
    }
}
