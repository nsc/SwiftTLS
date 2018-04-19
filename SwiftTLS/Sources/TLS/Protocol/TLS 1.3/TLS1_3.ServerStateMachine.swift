//
//  TLS1_3.ServerStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ServerStateMachine : TLSServerStateMachine
    {
        weak var server : TLSServer?
        var protocolHandler: TLS1_3.ServerProtocol? {
            return server?.protocolHandler as? TLS1_3.ServerProtocol
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
            print("Server: did send message \(TLSMessageNameForType(message.type))")
        }
        
        func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
        {
            self.didSendMessage(message)
            
            switch message.handshakeType
            {
            case .helloRetryRequest:
                try self.transition(to: .helloRetryRequestSent)
                break
                
            case .serverHello:
                try self.transition(to: .serverHelloSent)
                
                try self.protocolHandler!.sendEncryptedExtensions()
                
            case .encryptedExtensions:
                try self.transition(to: .encryptedExtensionsSent)
                
                if self.protocolHandler!.isUsingPreSharedKey {
                    try self.protocolHandler!.sendFinished()
                }
                else {
                    try self.protocolHandler!.sendCertificate()
                }
                
            case .certificate:
                try self.transition(to: .certificateSent)
            
                try self.protocolHandler!.sendCertificateVerify()
                
            case .certificateVerify:
                try self.transition(to: .certificateVerifySent)

                try self.protocolHandler!.sendFinished()
                
            case .finished:
                try self.transition(to: .finishedSent)

            case .newSessionTicket:
                try self.transition(to: .newSessionTicketSent)

            default:
                print("Unsupported handshake message \(message.handshakeType)")
            }
        }
        
        func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
        {
            print("Server: did receive message \(TLSHandshakeMessageNameForType(message.handshakeType))")
            
            let handshakeType = message.handshakeType
            
            switch (handshakeType)
            {
            case .clientHello:
                try self.transition(to: .clientHelloReceived)
                
                if self.server!.cipherSuite == nil {
                    try self.protocolHandler!.sendHelloRetryRequest(for: message as! TLSClientHello)
                }
                else {
                    let clientHello = message as! TLSClientHello
                    try self.protocolHandler!.sendServerHello(for: clientHello)
                }
                
            case .finished:
                try self.transition(to: .finishedReceived)
                
                if self.server!.configuration.supportsSessionResumption && !(self.server!.serverNames?.isEmpty ?? true)  {
                    try self.protocolHandler!.sendNewSessionTicket()
                }
                                
            default:
                print("Unsupported handshake message \(handshakeType.rawValue)")
            }
        }
        
        func serverDidReceiveAlert(_ alert: TLSAlertMessage) {
            print("Server: did receive message \(alert.alertLevel) \(alert.alert)")
        }
        
        func serverDidConnect() throws {
            try transition(to: .connected)
        }
        
        func checkServerStateTransition(_ state : TLSState) -> Bool
        {
            if state == .idle {
                return true
            }
            
            switch (self.state)
            {
            case .idle, .helloRetryRequestSent:
                return state == .clientHelloReceived
                
            case .clientHelloReceived:
                return state == .serverHelloSent || state == .helloRetryRequestSent
                
            case .serverHelloSent :
                return state == .encryptedExtensionsSent

            case .encryptedExtensionsSent :
                if self.protocolHandler!.isUsingPreSharedKey {
                    return state == .finishedSent
                }
                
                return state == .certificateSent

            case .certificateSent:
                return state == .certificateVerifySent

            case .certificateVerifySent:
                return state == .finishedSent
                
            case .finishedSent:
                return state == .finishedReceived
                
            case .finishedReceived:
                return state == .connected || state == .newSessionTicketSent
                
            case .newSessionTicketSent:
                return state == .connected
                
            case .connected:
                return (state == .closeReceived || state == .closeSent || state == .newSessionTicketSent)
                
            default:
                return false
            }
        }
    }
}
