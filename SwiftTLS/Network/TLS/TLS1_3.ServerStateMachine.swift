//
//  TLS1_3.ServerStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 29.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

//extension TLS1_3 {
//    class ServerStateMachine : TLSServerStateMachine
//    {
//        weak var server : TLSServer?
//        var protocolHandler: TLS1_3.ServerProtocol? {
//            return server?.protocolHandler as? TLS1_3.ServerProtocol
//        }
//        
//        var state : TLSState = .idle {
//            willSet {
//                if !checkServerStateTransition(newValue) {
//                    fatalError("Server: Illegal state transition \(self.state) -> \(newValue)")
//                }
//            }
//        }
//        
//        init(server : TLSServer)
//        {
//            self.server = server
//            self.state = .idle
//        }
//        
//        func transitionTo(state: TLSState) throws {
//            if !checkServerStateTransition(state) {
//                throw TLSError.error("Server: Illegal state transition \(self.state) -> \(state)")
//            }
//            
//            self.state = state
//        }
//        
//        func reset() {
//            self.state = .idle
//        }
//        
//        func didSendMessage(_ message : TLSMessage)
//        {
//            print("Server: did send message \(TLSMessageNameForType(message.type))")
//        }
//        
//        func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
//        {
//            self.didSendMessage(message)
//            
//            switch message.handshakeType
//            {
//            case .serverHello:
//                try self.transitionTo(state: .serverHelloSent)
//                
//                try self.protocolHandler!.sendCertificate()
//                
//            case .certificate:
//                try self.protocolHandler!.sendFinished()
//                
//            case .finished:
//                try self.transitionTo(state: .finishedSent)
//                
//            default:
//                print("Unsupported handshake \(message.handshakeType)")
//            }
//        }
//        
//        func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
//        {
//            print("Server: did receive handshake message \(TLSMessageNameForType(message.type))")
//            
//            let handshakeType = message.handshakeType
//            
//            switch (handshakeType)
//            {
//            case .clientHello:
//                try self.transitionTo(state: .clientHelloReceived)
//                try self.protocolHandler!.sendServerHello()
//                
//            case .finished:
//                try self.transitionTo(state: .finishedReceived)
//                
//                try self.transitionTo(state: .connected)
//                
//            default:
//                print("Unsupported handshake \(handshakeType.rawValue)")
//            }
//        }
//        
//        func serverDidReceiveAlert(_ alert: TLSAlertMessage) {
//            print("Server: did receive message \(alert.alertLevel) \(alert.alert)")
//        }
//        
//        func serverDidConnect() throws {
//            try transitionTo(state: .connected)
//        }
//        
//        func checkServerStateTransition(_ state : TLSState) -> Bool
//        {
//            if state == .idle {
//                return true
//            }
//            
//            switch (self.state)
//            {
//            case .idle:
//                return state == .clientHelloReceived
//                
//            case .clientHelloReceived:
//                return state == .serverHelloSent
//                
//            case .serverHelloSent :
//                return state == .certificateSent
//                
//            case .certificateSent:
//                return state == .finishedSent
//                
//            case .finishedSent:
//                return state == .finishedReceived
//                
//            case .finishedReceived:
//                return state == .connected
//                
//            case .connected:
//                switch state {
//                case .closeSent, .closeReceived:
//                    return true
//                    
//                default:
//                    return false
//                }
//                
//            default:
//                return false
//            }
//        }
//    }
//}
