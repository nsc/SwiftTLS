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
        
        func transition(to state: TLSState) throws {
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
            log("Server: did send message \(TLSMessageNameForType(message.type))")
        }
        
        func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
        {
            self.didSendMessage(message)
            
            switch message.handshakeType
            {
            case .serverHello:
                try self.transition(to: .serverHelloSent)
                
                if self.server!.isReusingSession {
                    try self.protocolHandler!.sendChangeCipherSpec()
                }
                else {
                    try self.protocolHandler!.sendCertificate()
                }
                
            case .certificate:
                try self.transition(to: .certificateSent)
                
                if self.server!.cipherSuite!.needsServerKeyExchange() {
                    try self.protocolHandler!.sendServerKeyExchange()
                }
                else {
                    try self.protocolHandler!.sendServerHelloDone()
                }
                
            case .serverKeyExchange:
                try self.transition(to: .serverKeyExchangeSent)
                try self.protocolHandler!.sendServerHelloDone()
                
            case .serverHelloDone:
                try self.transition(to: .serverHelloDoneSent)
                
            case .finished:
                try self.transition(to: .finishedSent)
                
            default:
                log("Unsupported handshake message \(message.handshakeType)")
            }
        }
        
        func didSendChangeCipherSpec() throws
        {
            log("did send change cipher spec")
            try self.transition(to: .changeCipherSpecSent)
            try self.protocolHandler!.sendFinished()
        }
        
        func didReceiveChangeCipherSpec() throws
        {
            log("did receive change cipher spec")
            try self.transition(to: .changeCipherSpecReceived)
        }
        
        func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
        {
            log("Server: did receive message \(TLSHandshakeMessageNameForType(message.handshakeType))")
            
            let handshakeType = message.handshakeType
            
            switch (handshakeType)
            {
            case .clientHello:
                try self.transition(to: .clientHelloReceived)
                let clientHello = message as! TLSClientHello
                try self.protocolHandler!.sendServerHello(for: clientHello)
                
            case .clientKeyExchange:
                try self.transition(to: .clientKeyExchangeReceived)
                
            case .finished:
                try self.transition(to: .finishedReceived)
                
                if !self.server!.isReusingSession {
                    try self.protocolHandler!.sendChangeCipherSpec()
                }
                
            default:
                log("Unsupported handshake \(handshakeType.rawValue)")
            }
        }
        
        func serverDidReceiveAlert(_ alert: TLSAlertMessage) {
            log("Server: did receive message \(alert.alertLevel) \(alert.alert)")
        }
        
        func serverDidConnect() throws {
            try transition(to: .connected)
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
