//
//  TLSStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 30.08.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public enum TLSState
{
    case idle
    case clientHelloSent
    case clientHelloReceived
    case serverHelloSent
    case serverHelloReceived
    case certificateSent
    case certificateReceived
    case certificateRequestSent
    case certificateRequestReceived
    case certificateVerifySent
    case certificateVerifyReceived
    case changeCipherSpecSent
    case changeCipherSpecReceived
    case finishedSent
    case finishedReceived
    case connected
    case closeSent
    case closeReceived
    case error
    
    case alertSent
    case alertReceived
    case applicationDataSent
    case applicationDataReceived
    
    // TLS 1.3
    case encryptedExtensionsSent
    case encryptedExtensionsReceived
    case newSessionTicketSent
    case newSessionTicketReceived
    case helloRetryRequestSent
    case helloRetryRequestReceived
    case endOfEarlyDataSent
    case endOfEarlyDataReceived
    case keyUpdateSent
    case keyUpdateReceived
    
    // TLS 1.2
    case helloRequestSent
    case helloRequestReceived
    case serverKeyExchangeSent
    case serverKeyExchangeReceived
    case serverHelloDoneSent
    case serverHelloDoneReceived
    case clientKeyExchangeSent
    case clientKeyExchangeReceived
    case certificateURLSent
    case certificateURLReceived
    case certificateStatusSent
    case certificateStatusReceived
}

extension TLSMessageType {
    var sentReceivedStates: (TLSState, TLSState) {
        switch self {
        case .handshake(let handshakeType):
            switch handshakeType {
            case .clientHello:
                return (.clientHelloSent, .clientHelloReceived)
                
            case .serverHello:
                return (.serverHelloSent, .serverHelloReceived)
                
            case .certificate:
                return (.certificateSent, .certificateReceived)
                
            case .certificateRequest:
                return (.certificateRequestSent, .certificateRequestReceived)
                
            case .certificateVerify:
                return (.certificateVerifySent, .certificateVerifyReceived)
                
            case .finished:
                return (.finishedSent, .finishedReceived)
                
            case .serverKeyExchange:
                return (.serverKeyExchangeSent, .serverKeyExchangeReceived)
                
            case .serverHelloDone:
                return (.serverHelloDoneSent, .serverHelloDoneReceived)
                
            case .clientKeyExchange:
                return (.clientKeyExchangeSent, .clientKeyExchangeReceived)
                
            case .helloRequest:
                return (.helloRequestSent, .helloRequestReceived)
                
            case .certificateURL:
                return (.certificateURLSent, .certificateURLReceived)
                
            case .certificateStatus:
                return (.certificateStatusSent, .certificateStatusReceived)

            case .newSessionTicket:
                return (.newSessionTicketSent, .newSessionTicketReceived)

            case .endOfEarlyData:
                return (.endOfEarlyDataSent, .endOfEarlyDataReceived)
                
            case .helloRetryRequest:
                return (.helloRetryRequestSent, .helloRetryRequestReceived)
                
            case .encryptedExtensions:
                return (.encryptedExtensionsSent, .encryptedExtensionsReceived)
                
            case .keyUpdate:
                return (.keyUpdateSent, .keyUpdateReceived)
                
            default:
                fatalError("Unknown message \(self)")
            }
        
        case .changeCipherSpec:
            return (.changeCipherSpecSent, .changeCipherSpecReceived)

        case .alert(_, _):
            return (.alertSent, .alertReceived)
            
        case .applicationData:
            return (.applicationDataSent, .applicationDataReceived)
        }
    }
    
    var sentState: TLSState {
        return sentReceivedStates.0
    }

    var receivedState: TLSState {
        return sentReceivedStates.1
    }
}
    
public protocol TLSConnectionStateMachine : AnyObject
{
    var state : TLSState { get set }
    
    func reset()
    
    func didSendMessage(_ message : TLSMessage) throws
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func didReceiveChangeCipherSpec() throws
    func didSendChangeCipherSpec() throws
    func didReceiveAlert(_ alert : TLSAlertMessage)
    func didConnect() throws
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    
    func transition(to state: TLSState) throws
    func actOnCurrentState() throws
}

public extension TLSConnectionStateMachine
{
    func reset() {}
    func transition(to state: TLSState) throws {}
    func actOnCurrentState() throws {}
}

public protocol TLSClientStateMachine : TLSConnectionStateMachine
{
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func clientDidSendChangeCipherSpec() throws
    func clientDidReceiveChangeCipherSpec() throws
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func clientShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    func clientDidReceiveAlert(_ alert : TLSAlertMessage)
    func clientDidConnect() throws

    func checkClientStateTransition(_ state : TLSState) -> Bool
}

public extension TLSClientStateMachine
{
    func clientDidSendChangeCipherSpec() throws {}
    func clientDidReceiveChangeCipherSpec() throws {}
    func clientShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func clientDidReceiveAlert(_ alert : TLSAlertMessage) {}
    func clientDidConnect() throws {}
    
    func didSendMessage(_ message : TLSMessage) throws {
        log("Client: did send message \(TLSMessageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.clientDidSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.clientDidReceiveHandshakeMessage(message)
    }
    
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        try self.didSendMessage(message)
        try self.transition(to: message.type.sentState)
        try self.actOnCurrentState()
    }
    
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        log("Client: did receive message \(TLSHandshakeMessageNameForType(message.handshakeType))")
        try self.transition(to: message.type.receivedState)
        try self.actOnCurrentState()
    }

    func didSendChangeCipherSpec() throws {
        try self.clientDidSendChangeCipherSpec()
    }
    
    func didReceiveChangeCipherSpec() throws {
        try self.clientDidReceiveChangeCipherSpec()
    }
    
    func didConnect() throws {
        try self.clientDidConnect()
    }
    
    func didReceiveAlert(_ alert : TLSAlertMessage) {
        self.clientDidReceiveAlert(alert)
    }
    
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool {
        return self.clientShouldContinueHandshake(with: message)
    }
    
    func transition(to state: TLSState) throws {
        if !checkClientStateTransition(state) {
            log("Client: Illegal state transition \(self.state) -> \(state)")
            throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
        }
        
        self.state = state
    }
    
    func checkClientStateTransition(_ state : TLSState) -> Bool { return true}
}

protocol TLSServerStateMachine : TLSConnectionStateMachine
{
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func serverDidSendChangeCipherSpec() throws
    func serverDidReceiveChangeCipherSpec() throws
    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func serverShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    func serverDidReceiveAlert(_ alert : TLSAlertMessage)
    func serverDidConnect() throws
    
    func checkServerStateTransition(_ state : TLSState) -> Bool
}

extension TLSServerStateMachine
{
    func serverDidSendChangeCipherSpec() throws {}
    func serverDidReceiveChangeCipherSpec() throws {}
    func serverShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func serverDidReceiveAlert(_ alert : TLSAlertMessage) {}
    func serverDidConnect() throws {}
    
    func didSendMessage(_ message : TLSMessage) throws {
        log("Server: did send message \(TLSMessageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.serverDidSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.serverDidReceiveHandshakeMessage(message)
    }
    
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        try self.didSendMessage(message)
        try self.transition(to: message.type.sentState)
        try self.actOnCurrentState()
    }
    
    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        log("Server: did receive message \(TLSHandshakeMessageNameForType(message.handshakeType))")
        try self.transition(to: message.type.receivedState)
        try self.actOnCurrentState()
    }

    func didSendChangeCipherSpec() throws {
        try self.serverDidReceiveChangeCipherSpec()
    }

    func didReceiveChangeCipherSpec() throws {
        try self.serverDidReceiveChangeCipherSpec()
    }
    
    func didConnect() throws {
        log("server did connect")
        try self.serverDidConnect()
    }
    
    func didReceiveAlert(_ alert : TLSAlertMessage) {
        self.serverDidReceiveAlert(alert)
    }
    
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool {
        return self.serverShouldContinueHandshake(with: message)
    }
    
    func transition(to state: TLSState) throws {
        if !checkServerStateTransition(state) {
            log("Server: Illegal state transition \(self.state) -> \(state)")
            throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
        }
        
        self.state = state
    }
    
    func checkServerStateTransition(_ state : TLSState) -> Bool { return true }
}

