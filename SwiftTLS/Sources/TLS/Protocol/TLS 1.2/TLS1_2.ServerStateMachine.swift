//
//  ServerStateMachine1_2.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_2 {
    class ServerStateMachine : TLSServerStateMachine
    {
        weak var server : TLSServer?
        var protocolHandler: TLS1_2.ServerProtocol? {
            return server?.protocolHandler as? TLS1_2.ServerProtocol
        }
        
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
                    try self.protocolHandler!.sendChangeCipherSpec()
                }
                else {
                    try self.protocolHandler!.sendCertificate()
                }
                
            case .certificate:
                try self.transitionTo(state: .certificateSent)
                
                if self.server!.cipherSuite!.needsServerKeyExchange() {
                    try self.protocolHandler!.sendServerKeyExchange()
                }
                else {
                    try self.protocolHandler!.sendServerHelloDone()
                }
                
            case .serverKeyExchange:
                try self.transitionTo(state: .serverKeyExchangeSent)
                try self.protocolHandler!.sendServerHelloDone()
                
            case .serverHelloDone:
                try self.transitionTo(state: .serverHelloDoneSent)
                
            case .finished:
                try self.transitionTo(state: .finishedSent)
                
            default:
                print("Unsupported handshake message \(message.handshakeType)")
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
        
        func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
        {
            print("Server: did receive message \(TLSHandshakeMessageNameForType(message.handshakeType))")
            
            let handshakeType = message.handshakeType
            
            switch (handshakeType)
            {
            case .clientHello:
                try self.transitionTo(state: .clientHelloReceived)
                let clientHello = message as! TLSClientHello
                try self.protocolHandler!.sendServerHello(for: clientHello)
                
            case .clientKeyExchange:
                try self.transitionTo(state: .clientKeyExchangeReceived)
                
            case .finished:
                try self.transitionTo(state: .finishedReceived)
                
                if !self.server!.isReusingSession {
                    try self.protocolHandler!.sendChangeCipherSpec()
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
            
            switch (self.state, state)
            {
            case (.idle, .clientHelloReceived):
                return true
                
            case (.clientHelloReceived, .serverHelloSent):
                return true
                
            case (.serverHelloSent, .certificateSent) where !self.server!.isReusingSession,
                 (.serverHelloSent, .changeCipherSpecSent) where self.server!.isReusingSession:
                return true
                
            case (.certificateSent, .serverHelloDoneSent) where !self.server!.cipherSuite!.needsServerKeyExchange(),
                 (.certificateSent, .serverKeyExchangeSent) where self.server!.cipherSuite!.needsServerKeyExchange():
                return true
                
            case (.serverKeyExchangeSent, .serverHelloDoneSent):
                return true
                
            case (.serverHelloDoneSent, .clientKeyExchangeReceived):
                return true
                
            case (.clientKeyExchangeReceived, .changeCipherSpecReceived):
                return true
                
            case (.changeCipherSpecReceived, .finishedReceived):
                return true
                
            case (.finishedReceived, .changeCipherSpecSent) where !self.server!.isReusingSession,
                 (.finishedReceived, .connected) where self.server!.isReusingSession:
                return true
                
            case (.changeCipherSpecSent, .finishedSent):
                return true
                
            case (.finishedSent, .connected) where !self.server!.isReusingSession,
                 (.finishedSent, .changeCipherSpecReceived) where self.server!.isReusingSession:
                return true
                
            case (.connected, .closeSent),
                 (.connected, .closeReceived),
                 (.connected, .clientHelloReceived):
                return true
                
            default:
                return false
            }
        }
    }
}
