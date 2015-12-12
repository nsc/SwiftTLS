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
    case Idle
    case ClientHelloSent
    case ClientHelloReceived
    case ServerHelloSent
    case ServerHelloReceived
    case ServerKeyExchangeSent
    case ServerKeyExchangeReceived
    case ServerHelloDoneSent
    case ServerHelloDoneReceived
    case CertificateSent
    case CertificateReceived
    case ClientKeyExchangeSent
    case ClientKeyExchangeReceived
    case ChangeCipherSpecSent
    case ChangeCipherSpecReceived
    case FinishedSent
    case FinishedReceived
    case Connected
    case CloseSent
    case CloseReceived
    case Error
}




class TLSStateMachine : TLSContextStateMachine
{
    weak var context : TLSContext?
    
    var state : TLSState = .Idle {
        willSet {
            if !checkStateTransition(newValue) {
                fatalError((self.context!.isClient ? "Client" : "Server" ) + ": Illegal state transition \(self.state) -> \(newValue)")
            }
        }
    }
    
    
    init(context : TLSContext)
    {
        self.context = context
        self.state = .Idle
    }
    
    func didSendMessage(message : TLSMessage)
    {
        print((self.context!.isClient ? "Client" : "Server" ) + ": did send message \(TLSMessageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(message : TLSHandshakeMessage) throws
    {
        self.didSendMessage(message)
        
        switch message.handshakeType
        {
        case .ClientHello:
            self.state = .ClientHelloSent
            
        case .ServerHello:
            self.state = .ServerHelloSent
            try self.context!.sendCertificate()
            
        case .Certificate:
            self.state = .CertificateSent
            
            if !self.context!.isClient {
                try self.context!.sendServerHelloDone()
            }
            
        case .ServerHelloDone:
            self.state = .ServerHelloDoneSent

        case .ClientKeyExchange:
            self.state = .ClientKeyExchangeSent
            try self.context!.sendChangeCipherSpec()

        case .Finished:
            self.state = .FinishedSent
            
        default:
            print("Unsupported handshake \(message.handshakeType)")
        }
    }
    
    func didSendChangeCipherSpec() throws
    {
        print("did send change cipher spec")
        self.state = .ChangeCipherSpecSent
        try self.context!.sendFinished()
    }
    
    func didReceiveChangeCipherSpec()
    {
        print("did receive change cipher spec")
        self.state = .ChangeCipherSpecReceived
    }

    func didReceiveHandshakeMessage(message : TLSHandshakeMessage) throws
    {
        print((self.context!.isClient ? "Client" : "Server" ) + ": did receive handshake message \(TLSMessageNameForType(message.type))")

        let handshakeType = message.handshakeType
            
        switch (handshakeType)
        {
        case .ClientHello:
            self.state = .ClientHelloReceived
            try self.context!.sendServerHello()
            
        case .ServerHello:
            self.state = .ServerHelloReceived
            
        case .Certificate:
            self.state = .CertificateReceived
            
        case .ServerKeyExchange:
            self.state = .ServerKeyExchangeReceived
            
        case .ServerHelloDone:
            self.state = .ServerHelloDoneReceived
            try self.context!.sendClientKeyExchange()
            
        case .ClientKeyExchange:
            self.state = .ClientKeyExchangeReceived
            
        case .Finished:
            self.state = .FinishedReceived
            
            if !self.context!.isClient {
                try self.context!.sendChangeCipherSpec()
            }
            
        default:
            print("unsupported handshake \(handshakeType.rawValue)")
        }
    }


    func advanceState(state : TLSState) -> Bool
    {
        if checkStateTransition(state) {
            self.state = state
            
            return true
        }
        
        return false
    }
    
    
    func checkClientStateTransition(state : TLSState) -> Bool
    {
        switch (self.state)
        {
        case .Idle where state == .ClientHelloSent:
            return true
            
        case .ClientHelloSent where state == .ServerHelloReceived:
            return true
            
        case .ServerHelloReceived where state == .CertificateReceived:
            return true
            
        case .CertificateReceived:
            if self.context!.cipherSuite!.needsServerKeyExchange() {
                if state == .ServerKeyExchangeReceived {
                    return true
                }
            }
            else if state == .ServerHelloDoneReceived {
                return true
            }
            
        case .ServerKeyExchangeReceived where state == .ServerHelloDoneReceived:
            return true
            
        case .ServerHelloDoneReceived where state == .ClientKeyExchangeSent:
            return true
            
        case .ClientKeyExchangeSent where state == .ChangeCipherSpecSent:
            return true
            
        case .ChangeCipherSpecSent where state == .FinishedSent:
            return true
            
        case .FinishedSent where state == .ChangeCipherSpecReceived:
            return true
            
        case .ChangeCipherSpecReceived where state == .FinishedReceived:
            return true
            
        case .FinishedReceived where state == .Connected:
            return true
            
        case .Connected where (state == .CloseReceived || state == .CloseSent):
            return true
            
        default:
            return false
        }
        
        return false
    }
    
    func checkServerStateTransition(state : TLSState) -> Bool
    {
        switch (self.state)
        {
        case .Idle where state == .ClientHelloReceived:
            return true

        case .ClientHelloReceived where state == .ServerHelloSent:
            return true
            
        case .ServerHelloSent where state == .CertificateSent:
            return true
            
        case .CertificateSent:
            if self.context!.cipherSuite!.needsServerKeyExchange() {
                if state == .ServerKeyExchangeSent {
                    return true
                }
            }
            else if state == .ServerHelloDoneSent {
                return true
            }
            
        case .ServerKeyExchangeSent where state == .ServerHelloDoneSent:
            return true
            
        case .ServerHelloDoneSent where state == .ClientKeyExchangeReceived:
            return true
            
        case .ClientKeyExchangeReceived where state == .ChangeCipherSpecReceived:
            return true
            
        case .ChangeCipherSpecReceived where state == .FinishedReceived:
            return true
            
        case .FinishedReceived where state == .ChangeCipherSpecSent:
            return true
            
        case .ChangeCipherSpecSent where state == .FinishedSent:
            return true
            
        case .FinishedSent where state == .Connected:
            return true
            
        default:
            return false
        }
        
        return false
    }
    
    func checkStateTransition(state : TLSState) -> Bool
    {
        if self.context!.isClient {
            return checkClientStateTransition(state)
        }
        else {
            return checkServerStateTransition(state)
        }
    }
}