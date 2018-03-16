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
                try self.protocolHandler!.sendChangeCipherSpec()
                
            case .finished:
                try self.transitionTo(state: .finishedSent)
                
            default:
                fatalError("Unsupported handshake message \(message.handshakeType)")
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
                try self.protocolHandler!.sendClientKeyExchange()
                
            case .finished:
                try self.transitionTo(state: .finishedReceived)
                
            default:
                fatalError("Unsupported handshake message \(handshakeType.rawValue)")
            }
        }
        
        func didSendChangeCipherSpec() throws
        {
            print("did send change cipher spec")
            try self.transitionTo(state: .changeCipherSpecSent)
            try self.protocolHandler!.sendFinished()
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
}
