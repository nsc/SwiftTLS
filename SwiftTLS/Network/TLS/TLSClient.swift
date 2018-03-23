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
    internal var clientProtocolHandler: TLSClientProtocol! {
        get {
            return self.protocolHandler as! TLSClientProtocol
        }
    }
    internal var clientContext: TLSClientContext
    override public var context: TLSContext {
        return clientContext
    }
    
    internal var keyExchangesAnnouncedToServer: [NamedGroup : KeyExchange] = [:]
    
    override init(configuration: TLSConfiguration, dataProvider : TLSDataProvider? = nil)
    {
        self.clientContext = TLSClientContext()
        super.init(configuration: configuration, dataProvider: dataProvider)
        
        var protocolVersion = self.configuration.supportedVersions.first
        if protocolVersion == nil {
            protocolVersion = .v1_2
        }
        
        setupClient(with: protocolVersion!)
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
            try self.clientProtocolHandler.handleServerHello(serverHello)

        case .helloRetryRequest:
            let helloRetryRequest = message as! TLSHelloRetryRequest
            try self.clientProtocolHandler.handleServerHello(helloRetryRequest)

        case .certificate:
            let certificateMessage = message as! TLSCertificateMessage
            self.protocolHandler.handleCertificate(certificateMessage)
            
        case .finished:
            try self.protocolHandler.handleFinished(message as! TLSFinished)
            
        default:
            try self.protocolHandler.handleMessage(message)
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
        
        try self.clientProtocolHandler.sendClientHello()
    }
    
    func setupClient(with version: TLSProtocolVersion)
    {
        let state = self.stateMachine?.state
        
        switch version {
        case TLSProtocolVersion.v1_2:
            self.protocolHandler    = TLS1_2.ClientProtocol(client: self)
            self.stateMachine       = TLS1_2.ClientStateMachine(client: self)
            self.recordLayer        = TLS1_2.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)

        case TLSProtocolVersion.v1_3:
            self.protocolHandler    = TLS1_3.ClientProtocol(client: self)
            self.stateMachine       = TLS1_3.ClientStateMachine(client: self)
            self.recordLayer        = TLS1_3.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)

        default:
            fatalError("Unsupported protocol \(version)")
        }
        
        if let state = state {
            self.stateMachine!.state = state
        }
    }
}
