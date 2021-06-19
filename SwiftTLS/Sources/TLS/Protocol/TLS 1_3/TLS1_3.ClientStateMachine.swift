//
//  TLS1_3.ClientStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ClientStateMachine : TLSClientStateMachine
    {
        weak var client : TLSClient?
        var protocolHandler: TLS1_3.ClientProtocol? {
            return client?.protocolHandler as? TLS1_3.ClientProtocol
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
        
        func reset() {
            self.state = .idle
        }
        
        func clientDidReceiveAlert(_ alert: TLSAlertMessage) {
            log("Client: did receive message \(alert.alertLevel) \(alert.alert)")
        }
        
        func clientDidConnect() throws {
            if let client = self.client {
                if case .accepted = (client.clientProtocolHandler as! ClientProtocol).clientHandshakeState.earlyDataState {
                    client.earlyDataWasAccepted = true
                } else {
                    client.earlyDataWasAccepted = false
                }
            }
            try transition(to: .connected)
        }
        
        func checkClientStateTransition(_ state : TLSState) -> Bool
        {
            if state == .idle {
                return true
            }
            
            switch (self.state)
            {
            case .idle:
                return state == .clientHelloSent
                
            case .clientHelloSent:
                return state == .serverHelloReceived || state == .helloRetryRequestReceived
                
            case .helloRetryRequestReceived:
                return state == .clientHelloSent
                
            case .serverHelloReceived:
                return state == .encryptedExtensionsReceived
                
            case .encryptedExtensionsReceived:
                if self.protocolHandler!.isUsingPreSharedKey {
                    return state == .finishedReceived
                }
                
                return state == .certificateRequestReceived || state == .certificateReceived
                
            case .certificateRequestReceived:
                return state == .certificateReceived
                
            case .certificateReceived:
                return state == .certificateVerifyReceived
                
            case .certificateVerifyReceived:
                return state == .finishedReceived
                
            case .finishedSent:
                return state == .connected

            case .finishedReceived:
                return state == .finishedSent || state == .endOfEarlyDataSent
                
            case .endOfEarlyDataSent:
                return state == .finishedSent
                
            case .newSessionTicketReceived:
                return (state == .connected || state == .newSessionTicketReceived)
                
            case .connected:
                return (state == .closeReceived || state == .closeSent || state == .newSessionTicketReceived)
                                
            default:
                return false
            }
        }
    }
}
