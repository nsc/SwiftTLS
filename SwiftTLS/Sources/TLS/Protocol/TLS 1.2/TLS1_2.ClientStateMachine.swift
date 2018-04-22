//
//  ClientStateMachine1_2.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_2 {
    
    class ClientStateMachine : TLSClientStateMachine
    {
        weak var client : TLSClient?
        var protocolHandler: TLS1_2.ClientProtocol? {
            return client?.protocolHandler as? TLS1_2.ClientProtocol
        }

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
            log("Client: did send message \(TLSMessageNameForType(message.type))")
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
                try self.protocolHandler!.sendChangeCipherSpec()
                
            case .finished:
                try self.transitionTo(state: .finishedSent)
                
            default:
                fatalError("Unsupported handshake message \(message.handshakeType)")
            }
        }
        
        func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
        {
            log("Client: did receive message \(TLSHandshakeMessageNameForType(message.handshakeType))")
            
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
                try self.protocolHandler!.sendClientKeyExchange()
                
            case .finished:
                try self.transitionTo(state: .finishedReceived)
                if self.client!.isReusingSession {
                    try self.protocolHandler!.sendChangeCipherSpec()
                }
                
            default:
                fatalError("Unsupported handshake message \(handshakeType.rawValue)")
            }
        }
        
        func didSendChangeCipherSpec() throws
        {
            log("did send change cipher spec")
            try self.transitionTo(state: .changeCipherSpecSent)
            try self.protocolHandler!.sendFinished()
        }
        
        func didReceiveChangeCipherSpec() throws
        {
            log("did receive change cipher spec")
            try self.transitionTo(state: .changeCipherSpecReceived)
        }
        
        func clientDidReceiveAlert(_ alert: TLSAlertMessage) {
            log("Client: did receive message \(alert.alertLevel) \(alert.alert)")
        }
        
        func clientDidConnect() throws {
            try transitionTo(state: .connected)
        }
        
        func checkClientStateTransition(_ state : TLSState) -> Bool
        {
            if state == .idle {
                return true
            }
            
            switch (self.state, state)
            {
            case (.idle, .clientHelloSent):
                return true
                
            case (.clientHelloSent, .serverHelloReceived):
                return true
                
            case (.serverHelloReceived, .certificateReceived) where !self.client!.isReusingSession,
                 (.serverHelloReceived, .changeCipherSpecReceived) where self.client!.isReusingSession:
                return true
                
            case (.certificateReceived, .serverKeyExchangeReceived) where self.client!.cipherSuite!.needsServerKeyExchange(),
                 (.certificateReceived, .serverHelloDoneReceived) where !self.client!.cipherSuite!.needsServerKeyExchange():
                return true
                
            case (.serverKeyExchangeReceived, .serverHelloDoneReceived):
                return true
                
            case (.serverHelloDoneReceived, .clientKeyExchangeSent):
                return true
                
            case (.clientKeyExchangeSent, .changeCipherSpecSent):
                return true
                
            case (.changeCipherSpecSent, .finishedSent):
                return true
                
            case (.finishedSent, .changeCipherSpecReceived) where !self.client!.isReusingSession,
                 (.finishedSent, .connected) where self.client!.isReusingSession:
                return true
                
            case (.changeCipherSpecReceived, .finishedReceived):
                return true
                
            case (.finishedReceived, .connected) where !self.client!.isReusingSession,
                 (.finishedReceived, .changeCipherSpecSent) where self.client!.isReusingSession:
                return true
                
            case (.connected, .closeReceived),
                 (.connected, .closeSent),
                 (.connected, .clientHelloSent):
                return true
                
            default:
                return false
            }
        }
    }
}
