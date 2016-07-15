//
//  TLSStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 30.08.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSState
{
    case idle
    case clientHelloSent
    case clientHelloReceived
    case serverHelloSent
    case serverHelloReceived
    case serverKeyExchangeSent
    case serverKeyExchangeReceived
    case serverHelloDoneSent
    case serverHelloDoneReceived
    case certificateSent
    case certificateReceived
    case clientKeyExchangeSent
    case clientKeyExchangeReceived
    case changeCipherSpecSent
    case changeCipherSpecReceived
    case finishedSent
    case finishedReceived
    case connected
    case closeSent
    case closeReceived
    case error
}




class TLSStateMachine : TLSContextStateMachine
{
    weak var context : TLSContext?
    
    var state : TLSState = .idle {
        willSet {
            if !checkStateTransition(newValue) {
                fatalError((self.context!.isClient ? "Client" : "Server" ) + ": Illegal state transition \(self.state) -> \(newValue)")
            }
        }
    }
    
    
    init(context : TLSContext)
    {
        self.context = context
        self.state = .idle
    }
    
    func transitionTo(state: TLSState) throws {
        if !checkStateTransition(state) {
            throw TLSError.error((self.context!.isClient ? "Client" : "Server" ) + ": Illegal state transition \(self.state) -> \(state)")
        }
        
        self.state = state
    }
    
    func didSendMessage(_ message : TLSMessage)
    {
        print((self.context!.isClient ? "Client" : "Server" ) + ": did send message \(TLSMessageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        self.didSendMessage(message)
        
        switch message.handshakeType
        {
        case .clientHello:
            try self.transitionTo(state: .clientHelloSent)
            
        case .serverHello:
            try self.transitionTo(state: .serverHelloSent)
            try self.context!.sendCertificate()
            
        case .certificate:
            try self.transitionTo(state: .certificateSent)
            
            if !self.context!.isClient {
                if self.context!.cipherSuite!.needsServerKeyExchange() {
                    try self.context!.sendServerKeyExchange()
                }
                else {
                    try self.context!.sendServerHelloDone()
                }
            }
            
        case .serverKeyExchange:
            try self.transitionTo(state: .serverKeyExchangeSent)
            try self.context!.sendServerHelloDone()

        case .serverHelloDone:
            try self.transitionTo(state: .serverHelloDoneSent)

        case .clientKeyExchange:
            try self.transitionTo(state: .clientKeyExchangeSent)
            try self.context!.sendChangeCipherSpec()

        case .finished:
            try self.transitionTo(state: .finishedSent)
            
        default:
            print("Unsupported handshake \(message.handshakeType)")
        }
    }
    
    func didSendChangeCipherSpec() throws
    {
        print("did send change cipher spec")
        try self.transitionTo(state: .changeCipherSpecSent)
        try self.context!.sendFinished()
    }
    
    func didReceiveChangeCipherSpec() throws
    {
        print("did receive change cipher spec")
        try self.transitionTo(state: .changeCipherSpecReceived)
    }

    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        print("Server: did receive handshake message \(TLSMessageNameForType(message.type))")
        
        let handshakeType = message.handshakeType
        
        switch (handshakeType)
        {
        case .clientHello:
            try self.transitionTo(state: .clientHelloReceived)
            try self.context!.sendServerHello()
            
        case .clientKeyExchange:
            try self.transitionTo(state: .clientKeyExchangeReceived)
            
        case .finished:
            try self.transitionTo(state: .finishedReceived)
            
            try self.context!.sendChangeCipherSpec()
            
        default:
            print("unsupported handshake \(handshakeType.rawValue)")
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
            try self.context!.sendClientKeyExchange()

        case .finished:
            try self.transitionTo(state: .finishedReceived)

        default:
            print("unsupported handshake \(handshakeType.rawValue)")
        }
    }

    func didReceiveAlert(_ alert: TLSAlertMessage) {
        print((self.context!.isClient ? "Client" : "Server" ) + ": did receive message \(alert.alertLevel) \(alert.alert)")
    }

    func advanceState(_ state : TLSState) -> Bool
    {
        if checkStateTransition(state) {
            self.state = state
            
            return true
        }
        
        return false
    }
    
    
    func checkClientStateTransition(_ state : TLSState) -> Bool
    {
        switch (self.state)
        {
        case .idle where state == .clientHelloSent:
            return true
            
        case .clientHelloSent where state == .serverHelloReceived:
            return true
            
        case .serverHelloReceived where state == .certificateReceived:
            return true
            
        case .certificateReceived:
            if self.context!.cipherSuite!.needsServerKeyExchange() {
                if state == .serverKeyExchangeReceived {
                    return true
                }
            }
            else if state == .serverHelloDoneReceived {
                return true
            }
            
        case .serverKeyExchangeReceived where state == .serverHelloDoneReceived:
            return true
            
        case .serverHelloDoneReceived where state == .clientKeyExchangeSent:
            return true
            
        case .clientKeyExchangeSent where state == .changeCipherSpecSent:
            return true
            
        case .changeCipherSpecSent where state == .finishedSent:
            return true
            
        case .finishedSent where state == .changeCipherSpecReceived:
            return true
            
        case .changeCipherSpecReceived where state == .finishedReceived:
            return true
            
        case .finishedReceived where state == .connected:
            return true
            
        case .connected where (state == .closeReceived || state == .closeSent):
            return true
            
        default:
            return false
        }
        
        return false
    }
    
    func checkServerStateTransition(_ state : TLSState) -> Bool
    {
        switch (self.state)
        {
        case .idle where state == .clientHelloReceived:
            return true

        case .clientHelloReceived where state == .serverHelloSent:
            return true
            
        case .serverHelloSent where state == .certificateSent:
            return true
            
        case .certificateSent:
            if self.context!.cipherSuite!.needsServerKeyExchange() {
                if state == .serverKeyExchangeSent {
                    return true
                }
            }
            else if state == .serverHelloDoneSent {
                return true
            }
            
        case .serverKeyExchangeSent where state == .serverHelloDoneSent:
            return true
            
        case .serverHelloDoneSent where state == .clientKeyExchangeReceived:
            return true
            
        case .clientKeyExchangeReceived where state == .changeCipherSpecReceived:
            return true
            
        case .changeCipherSpecReceived where state == .finishedReceived:
            return true
            
        case .finishedReceived where state == .changeCipherSpecSent:
            return true
            
        case .changeCipherSpecSent where state == .finishedSent:
            return true
            
        case .finishedSent where state == .connected:
            return true
            
        default:
            return false
        }
        
        return false
    }
    
    func checkStateTransition(_ state : TLSState) -> Bool
    {
        if self.context!.isClient {
            return checkClientStateTransition(state)
        }
        else {
            return checkServerStateTransition(state)
        }
    }
}
