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

    public init(configuration: TLSConfiguration, context: TLSContext? = nil)
    {
        super.init(configuration: configuration, context: context, socket: TCPSocket())

        if !(context is TLSClientContext) {
            self.context = configuration.createClientContext()
        }
        
        var protocolVersion = self.configuration.supportedVersions.first
        if protocolVersion == nil {
            protocolVersion = .v1_2
        }
        
        setupClient(with: protocolVersion!)
    }
    
    func startConnection(withEarlyData earlyData: [UInt8]? = nil) async throws
    {
        reset()
        
        self.earlyData = earlyData
        
        do {
            try await clientProtocolHandler.connect()
        } catch TLSError.alert(let alert, alertLevel: let alertLevel, let message) {
            if alertLevel == .fatal {
                try await abortHandshake(with: alert)
            }
            
            if let message = message {
                log(message)
            }
            
            throw TLSError.alert(alert, alertLevel: alertLevel, message: message)
        }
        
        isConnected = true
        
        self.handshakeMessages = []
    }
    
    func setupClient(with version: TLSProtocolVersion)
    {
        switch version {
        case TLSProtocolVersion.v1_2:
            self.protocolHandler    = TLS1_2.ClientProtocol(client: self)
            self.recordLayer        = TLS1_2.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)

        case TLSProtocolVersion.v1_3:
            self.protocolHandler    = TLS1_3.ClientProtocol(client: self)
            self.recordLayer        = TLS1_3.RecordLayer(connection: self, dataProvider: self.recordLayer?.dataProvider)

        default:
            fatalError("Unsupported protocol \(version)")
        }
    }
}

extension TLSClient : ClientSocketProtocol
{
    var clientSocket: ClientSocketProtocol {
        return (self.socket as! ClientSocketProtocol)
    }
    
    public func connect(_ address: IPAddress, withEarlyData earlyData: Data) async throws
    {
        try await clientSocket.connect(address)
        try await startConnection(withEarlyData: [UInt8](earlyData))
    }
    
    // Connect with early data.
    public func connect(hostname: String, port: UInt16 = 443, withEarlyData earlyData: Data) async throws
    {
        self.earlyData = [UInt8](earlyData)
        
        try await connect(hostname: hostname, port: port)
    }
    
    public func connect(hostname: String, port: UInt16 = 443) async throws
    {
        await ConnectionNumber.increase()
        try await Log.withConnectionNumber(ConnectionNumber.value) {
            if let address = IPv4Address.addressWithString(hostname, port: port) {
                var hostNameAndPort = hostname
                if port != 443 {
                    hostNameAndPort = "\(hostname):\(port)"
                }
                self.serverNames = [hostNameAndPort]
                
                try await connect(address)
            }
            else {
                throw TLSError.error("Error: Could not resolve host \(hostname)")
            }
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
    public func connect(_ address: IPAddress) async throws
    {
        try await clientSocket.connect(address)
        try await self.startConnection(withEarlyData: self.earlyData)
    }
}
