//
//  TLSServer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

public class TLSServer : TLSConnection
{
    internal var serverProtocolHandler: TLSServerProtocol! {
        get {
            return (self.protocolHandler as! TLSServerProtocol)
        }
    }

    var clientHello: TLSClientHello? = nil
    
    var clientKeyShare: KeyShareEntry? = nil
    var earlyDataResponseHandler: TLSServer.EarlyDataResponseHandler? = nil
    
    public convenience init(identity: Identity)
    {
        let configuration = TLSConfiguration(identity: identity)
        self.init(configuration: configuration)
    }
    
    public init(configuration: TLSConfiguration, context: TLSContext? = nil)
    {
        super.init(configuration: configuration, context: context, socket: TCPSocket())
        
        if !(context is TLSServerContext) {
            self.context = configuration.createServerContext()
        }

        setupServer(with: configuration)
    }
    
    func _acceptConnection() throws
    {
        reset()
        
        do {
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
        case .clientHello:
            let clientHello = (message as! TLSClientHello)
            self.clientHello = clientHello
            try self.serverProtocolHandler.handleClientHello(clientHello)
            
        case .clientKeyExchange:
            try self.protocolHandler.handleMessage(message)

        case .finished:
            let finished = message as! TLSFinished
            try self.protocolHandler.handleFinished(finished)
            
        default:
            try self.protocolHandler.handleMessage(message)
        }
        
        try self.stateMachine?.didReceiveHandshakeMessage(message)
        
        return true
    }

    func setupServer(with configuration: TLSConfiguration, version: TLSProtocolVersion? = nil)
    {
        var version = version
        if version == nil {
            version = configuration.supportedVersions.first
        }
        
        let state = self.stateMachine?.state
        
        switch version!
        {
        case TLSProtocolVersion.v1_2:
            self.protocolHandler    = TLS1_2.ServerProtocol(server: self)
            self.stateMachine       = TLS1_2.ServerStateMachine(server: self)
            self.recordLayer        = TLS1_2.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)
            
        case TLSProtocolVersion.v1_3:
            self.protocolHandler    = TLS1_3.ServerProtocol(server: self)
            self.stateMachine       = TLS1_3.ServerStateMachine(server: self)
            self.recordLayer        = TLS1_3.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)
            
        default:
            fatalError("Unsupported protocol \(version!)")
        }
        
        if let state = state {
            self.stateMachine!.state = state
        }

        if let identity = configuration.identity {
            // we are currently only supporting RSA certificates
            self.signer = identity.signer(with: self.hashAlgorithm)
        }
    }
}

extension TLSServer : ServerSocketProtocol
{
    private var serverSocket: ServerSocketProtocol {
        return (self.socket as! ServerSocketProtocol)
    }
    
    public func listen(on address: IPAddress) throws {
        try self.serverSocket.listen(on: address)
    }
    
    public func acceptConnection() throws -> SocketProtocol {
        return try acceptConnection(withEarlyDataResponseHandler: nil)
    }
    
    public typealias EarlyDataResponseHandler = ((_ connection: TLSConnection, _ earlyData: Data) -> (Data?))
    
    /// Accept a connection
    ///
    /// - Parameter earlyDataResponseHandler: if the client sends early data and the server is configured
    ///                                       to accept it, the earlyDataResponseHandler is called with the early data
    ///                                       and it can return a response that is send with the first flight
    ///
    /// - Returns: the socket rerpresenting the client that has connected
    /// - Throws: Mainly TLSError I think :) (Make this more rigorous)
    public func acceptConnection(withEarlyDataResponseHandler earlyDataResponseHandler: EarlyDataResponseHandler?) throws -> SocketProtocol
    {
        let clientSocket = try self.serverSocket.acceptConnection() as! TCPSocket
        let clientTLSSocket = TLSServer(configuration: self.configuration, context: self.context)
        
        try BigInt.withContext { _ in
            clientTLSSocket.socket = clientSocket
            clientTLSSocket.signer = self.signer
            clientTLSSocket.configuration = self.configuration
            clientTLSSocket.recordLayer.dataProvider = clientSocket
            clientTLSSocket.context = self.context
            
            clientTLSSocket.earlyDataResponseHandler = earlyDataResponseHandler
            
            try clientTLSSocket._acceptConnection()
        }
        
        return clientTLSSocket
    }
    
    public enum AcceptConnectionResult
    {
        case error(Error)
        case client(TLSConnection)
    }
    
    public func acceptConnection(withEarlyDataResponseHandler earlyDataResponseHandler: EarlyDataResponseHandler?, completionHandler: @escaping (AcceptConnectionResult) -> ()) throws
    {
        let clientSocket = try self.serverSocket.acceptConnection() as! TCPSocket
        
        let queue = DispatchQueue.global()
        
        queue.async {
            BigInt.withContext { _ in
                if let address = clientSocket.peerName {
                    log("Connection from \(address)")
                }
                
                let clientTLSSocket = TLSServer(configuration: self.configuration, context: self.context)
                clientTLSSocket.socket = clientSocket
                clientTLSSocket.signer = self.signer
                clientTLSSocket.configuration = self.configuration
                clientTLSSocket.recordLayer.dataProvider = clientSocket
                clientTLSSocket.context = self.context
                
                clientTLSSocket.earlyDataResponseHandler = earlyDataResponseHandler
                
                do {
                    try clientTLSSocket._acceptConnection()
                } catch let error {
                    completionHandler(.error(error))
                }
                
                completionHandler(.client(clientTLSSocket))
                
                Thread.current.removeThreadNumber()
            }
        }
    }

}
