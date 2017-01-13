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
    internal var protocolHandler: TLSClientProtocol!
    internal var clientContext: TLSClientContext
    override public var context: TLSContext {
        return clientContext
    }
    
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
            try self.protocolHandler.handleServerHello(serverHello)
            
        case .certificate:
            let certificateMessage = message as! TLSCertificateMessage
            self.protocolHandler.handleCertificate(certificateMessage)
            
        case .serverKeyExchange, .serverHelloDone:
            try self.protocolHandler.handleMessage(message)
            
        case .finished:
            try self.protocolHandler.handleFinished(message as! TLSFinished)
            
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
        
        try self.protocolHandler.sendClientHello()
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
    
    func setupClient(with version: TLSProtocolVersion)
    {
        switch version {
        case TLSProtocolVersion.v1_2:
            self.protocolHandler = TLS1_2.ClientProtocol(client: self)
            self.stateMachine    = TLS1_2.ClientStateMachine(client: self)
            
        default:
            fatalError("Unsupported protocol \(version)")
        }
    }
}
