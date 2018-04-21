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
        
    override init(configuration: TLSConfiguration, context: TLSContext? = nil, dataProvider : TLSDataProvider? = nil)
    {
        super.init(configuration: configuration, context: context, dataProvider: dataProvider)

        if !(context is TLSClientContext) {
            self.context = configuration.createClientContext()
        }
        
        var protocolVersion = self.configuration.supportedVersions.first
        if protocolVersion == nil {
            protocolVersion = .v1_2
        }
        
        setupClient(with: protocolVersion!)
    }
    
    func startConnection(withEarlyData earlyData: Data? = nil) throws
    {
        reset()
        
        if let data = earlyData {
            var buffer = [UInt8](repeating: 0, count: data.count)
            buffer.withUnsafeMutableBufferPointer {
                _ = data.copyBytes(to: $0)
            }
            self.earlyData = buffer
        }
        
        do {
            try self.sendClientHello()
            try self.receiveNextTLSMessage()
        } catch TLSError.alert(alert: let alert, alertLevel: let alertLevel) {
            if alertLevel == .fatal {
                try abortHandshake(with: alert)
            }
            
            throw TLSError.alert(alert: alert, alertLevel: alertLevel)
        }
        
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
