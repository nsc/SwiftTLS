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
                try self.protocolHandler!.sendServerHello()
                
            case .clientKeyExchange:
                try self.transitionTo(state: .clientKeyExchangeReceived)
                
            case .finished:
                try self.transitionTo(state: .finishedReceived)
                
                if self.server!.isReusingSession {
                    try self.transitionTo(state: .connected)
                }
                else {
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
}
