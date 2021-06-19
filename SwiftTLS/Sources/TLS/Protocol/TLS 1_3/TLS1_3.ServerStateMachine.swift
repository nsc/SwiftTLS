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
        
        func reset() {
            self.state = .idle
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
                return state == .connected || state == .newSessionTicketSent
                
            case .connected:
                return (state == .closeReceived || state == .closeSent || state == .newSessionTicketSent)
                
            default:
                return false
            }
        }
    }
}
