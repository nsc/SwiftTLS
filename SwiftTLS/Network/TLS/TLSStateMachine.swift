//
//  TLSStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 30.08.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSState
{
    case idle
    case clientHelloSent
    case clientHelloReceived
    case serverHelloSent
    case serverHelloReceived
    case serverKeyExchangeSent
    case serverKeyExchangeReceived
    case serverHelloDoneSent
    case serverHelloDoneReceived
    case certificateSent
    case certificateReceived
    case clientKeyExchangeSent
    case clientKeyExchangeReceived
    case changeCipherSpecSent
    case changeCipherSpecReceived
    case finishedSent
    case finishedReceived
    case connected
    case closeSent
    case closeReceived
    case error
}

protocol TLSConnectionStateMachine
{
    func reset()
    
    func didSendMessage(_ message : TLSMessage) throws
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func didReceiveChangeCipherSpec() throws
    func didSendChangeCipherSpec() throws
    func didReceiveAlert(_ alert : TLSAlertMessage)
    func didConnect() throws
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
}

extension TLSConnectionStateMachine
{
    func reset() {}
}

protocol TLSClientStateMachine : TLSConnectionStateMachine
{
    func clientDidSendMessage(_ message : TLSMessage) throws
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func clientDidSendChangeCipherSpec() throws
    func clientDidReceiveChangeCipherSpec() throws
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func clientShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    func clientDidReceiveAlert(_ alert : TLSAlertMessage)
    func clientDidConnect() throws
}

extension TLSClientStateMachine
{
    func clientDidSendMessage(_ message : TLSMessage) throws {}
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func clientDidSendChangeCipherSpec() throws {}
    func clientDidReceiveChangeCipherSpec() throws {}
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func clientShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func clientDidReceiveAlert(_ alert : TLSAlertMessage) {}
    func clientDidConnect() throws {}
    
    func didSendMessage(_ message : TLSMessage) throws {
        try self.clientDidSendMessage(message)
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.clientDidSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.clientDidReceiveHandshakeMessage(message)
    }
    
    func didSendChangeCipherSpec() throws {
        try self.clientDidSendChangeCipherSpec()
    }
    
    func didReceiveChangeCipherSpec() throws {
        try self.clientDidReceiveChangeCipherSpec()
    }
    
    func didConnect() throws {
        try self.clientDidConnect()
    }
    
    func didReceiveAlert(_ alert : TLSAlertMessage) {
        self.clientDidReceiveAlert(alert)
    }
    
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool {
        return self.clientShouldContinueHandshake(with: message)
    }
}

protocol TLSServerStateMachine : TLSConnectionStateMachine
{
    func serverDidSendMessage(_ message : TLSMessage) throws
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func serverDidSendChangeCipherSpec() throws
    func serverDidReceiveChangeCipherSpec() throws
    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func serverShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    func serverDidReceiveAlert(_ alert : TLSAlertMessage)
    func serverDidConnect() throws
}

extension TLSServerStateMachine
{
    func serverDidSendMessage(_ message : TLSMessage) throws {}
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func serverDidSendChangeCipherSpec() throws {}
    func serverDidReceiveChangeCipherSpec() throws {}
    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func serverShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func serverDidReceiveAlert(_ alert : TLSAlertMessage) {}
    func serverDidConnect() throws {}
    
    func didSendMessage(_ message : TLSMessage) throws {
        try self.serverDidSendMessage(message)
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.serverDidSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.serverDidReceiveHandshakeMessage(message)
    }
    
    func didReceiveChangeCipherSpec() throws {
        try self.serverDidReceiveChangeCipherSpec()
    }
    
    func didConnect() throws {
        try self.serverDidConnect()
    }
    
    func didReceiveAlert(_ alert : TLSAlertMessage) {
        self.serverDidReceiveAlert(alert)
    }
    
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool {
        return self.serverShouldContinueHandshake(with: message)
    }
}

class ClientStateMachine : TLSClientStateMachine
{
    weak var client : TLSClient?
    
    var state : TLSState = .idle {
        willSet {
            if !checkClientStateTransition(newValue) {
                fatalError("Client: Illegal state transition \(self.state) -> \(newValue)")
            }
        }
    }
    
    init(client : TLSClient)
    {
        self.client = client
        self.state = .idle
    }
    
    func transitionTo(state: TLSState) throws {
        if !checkClientStateTransition(state) {
            throw TLSError.error("Client: Illegal state transition \(self.state) -> \(state)")
        }
        
        self.state = state
    }
    
    func reset() {
        self.state = .idle
    }
    
    func didSendMessage(_ message : TLSMessage)
    {
        print("Client: did send message \(TLSMessageNameForType(message.type))")
    }
    
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        self.didSendMessage(message)
        
        switch message.handshakeType
        {
        case .clientHello:
            try self.transitionTo(state: .clientHelloSent)
            
        case .certificate:
            try self.transitionTo(state: .certificateSent)
            
        case .clientKeyExchange:
            try self.transitionTo(state: .clientKeyExchangeSent)
            try self.client!.sendChangeCipherSpec()
            
        case .finished:
            try self.transitionTo(state: .finishedSent)
            
        default:
            print("Unsupported handshake \(message.handshakeType)")
        }
    }
    
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        print("Client: did receive handshake message \(TLSMessageNameForType(message.type))")
        
        let handshakeType = message.handshakeType
        
        switch (handshakeType)
        {
        case .serverHello:
            try self.transitionTo(state: .serverHelloReceived)
            
        case .certificate:
            try self.transitionTo(state: .certificateReceived)
            
        case .serverKeyExchange:
            try self.transitionTo(state: .serverKeyExchangeReceived)
            
        case .serverHelloDone:
            try self.transitionTo(state: .serverHelloDoneReceived)
            try self.client!.sendClientKeyExchange()
            
        case .finished:
            try self.transitionTo(state: .finishedReceived)
            
        default:
            print("Unsupported handshake \(handshakeType.rawValue)")
        }
    }

    func didSendChangeCipherSpec() throws
    {
        print("did send change cipher spec")
        try self.transitionTo(state: .changeCipherSpecSent)
        try self.client!.sendFinished()
    }
    
    func didReceiveChangeCipherSpec() throws
    {
        print("did receive change cipher spec")
        try self.transitionTo(state: .changeCipherSpecReceived)
    }

    func clientDidReceiveAlert(_ alert: TLSAlertMessage) {
        print("Client: did receive message \(alert.alertLevel) \(alert.alert)")
    }
    
    func clientDidConnect() throws {
        try transitionTo(state: .connected)
    }

    func checkClientStateTransition(_ state : TLSState) -> Bool
    {
        if state == .idle {
            return true
        }
        
        switch (self.state)
        {
        case .idle where state == .clientHelloSent:
            return true
            
        case .clientHelloSent where state == .serverHelloReceived:
            return true
            
        case .serverHelloReceived:
            // If we are reusing a former session, we need to transition to
            // changeCipherSpecReceived instead of certificateReceived
            if self.client!.isReusingSession {
                if state == .changeCipherSpecReceived {
                    return true
                }
            }
            
            return state == .certificateReceived
            
        case .certificateReceived:
            if self.client!.cipherSuite!.needsServerKeyExchange() {
                return state == .serverKeyExchangeReceived
            }
            
            return state == .serverHelloDoneReceived
            
        case .serverKeyExchangeReceived where state == .serverHelloDoneReceived:
            return true
            
        case .serverHelloDoneReceived where state == .clientKeyExchangeSent:
            return true
            
        case .clientKeyExchangeSent where state == .changeCipherSpecSent:
            return true
            
        case .changeCipherSpecSent where state == .finishedSent:
            return true
            
        case .finishedSent:
            if self.client!.isReusingSession {
                return state == .connected
            }
            
            return state == .changeCipherSpecReceived
            
        case .changeCipherSpecReceived where state == .finishedReceived:
            return true
            
        case .finishedReceived:
            if self.client!.isReusingSession {
                return state == .changeCipherSpecSent
            }
            
            return state == .connected
            
        case .connected where (state == .closeReceived || state == .closeSent || state == .clientHelloSent):
            return true
            
        default:
            return false
        }
    }
}

class ServerStateMachine : TLSServerStateMachine
{
    weak var server : TLSServer?
    
    var state : TLSState = .idle {
        willSet {
            if !checkServerStateTransition(newValue) {
                fatalError("Server: Illegal state transition \(self.state) -> \(newValue)")
            }
        }
    }
    
    init(server : TLSServer)
    {
        self.server = server
        self.state = .idle
    }
    
    func transitionTo(state: TLSState) throws {
        if !checkServerStateTransition(state) {
            throw TLSError.error("Server: Illegal state transition \(self.state) -> \(state)")
        }
        
        self.state = state
    }
    
    func reset() {
        self.state = .idle
    }
    
    func didSendMessage(_ message : TLSMessage)
    {
        print("Server: did send message \(TLSMessageNameForType(message.type))")
    }
    
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        self.didSendMessage(message)
        
        switch message.handshakeType
        {
        case .serverHello:
            try self.transitionTo(state: .serverHelloSent)
            
            if self.server!.isReusingSession {
                try self.server!.sendChangeCipherSpec()
            }
            else {
                try self.server!.sendCertificate()
            }
            
        case .certificate:
            try self.transitionTo(state: .certificateSent)
            
            if self.server!.cipherSuite!.needsServerKeyExchange() {
                try self.server!.sendServerKeyExchange()
            }
            else {
                try self.server!.sendServerHelloDone()
            }
            
        case .serverKeyExchange:
            try self.transitionTo(state: .serverKeyExchangeSent)
            try self.server!.sendServerHelloDone()

        case .serverHelloDone:
            try self.transitionTo(state: .serverHelloDoneSent)

        case .finished:
            try self.transitionTo(state: .finishedSent)
            
        default:
            print("Unsupported handshake \(message.handshakeType)")
        }
    }
    
    func didSendChangeCipherSpec() throws
    {
        print("did send change cipher spec")
        try self.transitionTo(state: .changeCipherSpecSent)
        try self.server!.sendFinished()
    }
    
    func didReceiveChangeCipherSpec() throws
    {
        print("did receive change cipher spec")
        try self.transitionTo(state: .changeCipherSpecReceived)
    }

    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        print("Server: did receive handshake message \(TLSMessageNameForType(message.type))")
        
        let handshakeType = message.handshakeType
        
        switch (handshakeType)
        {
        case .clientHello:
            try self.transitionTo(state: .clientHelloReceived)
            try self.server!.sendServerHello()
            
        case .clientKeyExchange:
            try self.transitionTo(state: .clientKeyExchangeReceived)
            
        case .finished:
            try self.transitionTo(state: .finishedReceived)
            
            if self.server!.isReusingSession {
                try self.transitionTo(state: .connected)
            }
            else {
                try self.server!.sendChangeCipherSpec()
            }
            
        default:
            print("Unsupported handshake \(handshakeType.rawValue)")
        }
    }
    
    func serverDidReceiveAlert(_ alert: TLSAlertMessage) {
        print("Server: did receive message \(alert.alertLevel) \(alert.alert)")
    }

    func serverDidConnect() throws {
        try transitionTo(state: .connected)
    }
    
    func checkServerStateTransition(_ state : TLSState) -> Bool
    {
        if state == .idle {
            return true
        }
        
        switch (self.state)
        {
        case .idle where state == .clientHelloReceived:
            return true

        case .clientHelloReceived where state == .serverHelloSent:
            return true
            
        case .serverHelloSent:
            if self.server!.isReusingSession {
                return state == .changeCipherSpecSent
            }
            
            return state == .certificateSent
            
        case .certificateSent:
            if self.server!.cipherSuite!.needsServerKeyExchange() {
                return state == .serverKeyExchangeSent
            }
            
            return state == .serverHelloDoneSent

        case .serverKeyExchangeSent where state == .serverHelloDoneSent:
            return true
            
        case .serverHelloDoneSent where state == .clientKeyExchangeReceived:
            return true
            
        case .clientKeyExchangeReceived where state == .changeCipherSpecReceived:
            return true
            
        case .changeCipherSpecReceived where state == .finishedReceived:
            return true
            
        case .finishedReceived:
            if self.server!.isReusingSession {
                return state == .connected
            }

            return state == .changeCipherSpecSent
            
        case .changeCipherSpecSent where state == .finishedSent:
            return true
            
        case .finishedSent:
            if self.server!.isReusingSession {
                return state == .changeCipherSpecReceived
            }
            
            return state == .connected
            
        case .connected:
            switch state {
            case .closeSent, .closeReceived, .clientHelloReceived:
                return true
                
            default:
                return false
            }
            
        default:
            return false
        }
    }
}
