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
    internal var protocolHandler: TLSServerProtocol!
    internal var serverContext: TLSServerContext
    override public var context: TLSContext {
        return serverContext
    }

    override init(configuration: TLSConfiguration, dataProvider : TLSDataProvider? = nil)
    {
        self.serverContext = TLSServerContext()
        
        super.init(configuration: configuration, dataProvider: dataProvider)
        
        setupServer(with: configuration)
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
            try self.protocolHandler.handleClientHello(clientHello)
            
        case .clientKeyExchange:
            try self.protocolHandler.handleMessage(message)
            
        case .finished:
            let finished = message as! TLSFinished
            try self.protocolHandler.handleFinished(finished)
            
        default:
            throw TLSError.error("Unsupported handshake \(handshakeType.rawValue)")
        }
        
        try self.stateMachine?.didReceiveHandshakeMessage(message)
    }

    func setupServer(with configuration: TLSConfiguration)
    {
        var version = configuration.supportedVersions.first
        if version == nil {
            version = TLSProtocolVersion.v1_2
        }
        
        switch version!
        {
        case TLSProtocolVersion.v1_2:
            self.protocolHandler = TLS1_2.ServerProtocol(server: self)
            self.stateMachine = TLS1_2.ServerStateMachine(server: self)
            if let identity = configuration.identity {
                // we are currently only supporting RSA
                if let rsa = identity.rsa {
                    self.signer = rsa
                }
            }
        
        default:
            fatalError("Unsupported version \(version!)")
            
        }
    }
}
