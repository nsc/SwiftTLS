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
        
        func reset() {
            self.state = .idle
        }
        
        func actOnCurrentState() throws
        {
            switch self.state
            {
            case .clientHelloReceived:
                guard let clientHello = server?.clientHello else {
                    fatalError("clientHello not available")
                }
                
                try self.protocolHandler!.sendServerHello(for: clientHello)

            case .serverHelloSent:
                if self.server!.isReusingSession {
                    try self.protocolHandler!.sendChangeCipherSpec()
                }
                else {
                    try self.protocolHandler!.sendCertificate()
                }
                
            case .certificateSent:
                if self.server!.cipherSuite!.needsServerKeyExchange() {
                    try self.protocolHandler!.sendServerKeyExchange()
                }
                else {
                    try self.protocolHandler!.sendServerHelloDone()
                }
                
            case .serverKeyExchangeSent:
                try self.protocolHandler!.sendServerHelloDone()
                
            case .finishedSent where !self.server!.isReusingSession:
                try serverDidConnect()
                
            case .finishedReceived:
                if !self.server!.isReusingSession {
                    try self.protocolHandler!.sendChangeCipherSpec()
                }
                else {
                    try serverDidConnect()
                }

            default:
                break
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
