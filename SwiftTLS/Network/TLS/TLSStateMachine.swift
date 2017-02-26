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
    case certificateRequestSent
    case certificateRequestReceived
    case certificateVerifySent
    case certificateVerifyReceived
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
    
    // TLS 1.3
    case encryptedExtensionsSent
    case encryptedExtensionsReceived
}

protocol TLSConnectionStateMachine
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
}

extension TLSConnectionStateMachine
{
    func reset() {}
}

protocol TLSClientStateMachine : TLSConnectionStateMachine
{
    func clientDidSendMessage(_ message : TLSMessage) throws
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func clientDidSendChangeCipherSpec() throws
    func clientDidReceiveChangeCipherSpec() throws
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func clientShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    func clientDidReceiveAlert(_ alert : TLSAlertMessage)
    func clientDidConnect() throws
}

extension TLSClientStateMachine
{
    func clientDidSendMessage(_ message : TLSMessage) throws {}
    func clientDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func clientDidSendChangeCipherSpec() throws {}
    func clientDidReceiveChangeCipherSpec() throws {}
    func clientDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func clientShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func clientDidReceiveAlert(_ alert : TLSAlertMessage) {}
    func clientDidConnect() throws {}
    
    func didSendMessage(_ message : TLSMessage) throws {
        try self.clientDidSendMessage(message)
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.clientDidSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.clientDidReceiveHandshakeMessage(message)
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
}

protocol TLSServerStateMachine : TLSConnectionStateMachine
{
    func serverDidSendMessage(_ message : TLSMessage) throws
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func serverDidSendChangeCipherSpec() throws
    func serverDidReceiveChangeCipherSpec() throws
    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func serverShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    func serverDidReceiveAlert(_ alert : TLSAlertMessage)
    func serverDidConnect() throws
}

extension TLSServerStateMachine
{
    func serverDidSendMessage(_ message : TLSMessage) throws {}
    func serverDidSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func serverDidSendChangeCipherSpec() throws {}
    func serverDidReceiveChangeCipherSpec() throws {}
    func serverDidReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {}
    func serverShouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func serverDidReceiveAlert(_ alert : TLSAlertMessage) {}
    func serverDidConnect() throws {}
    
    func didSendMessage(_ message : TLSMessage) throws {
        try self.serverDidSendMessage(message)
    }
    
    func didSendHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.serverDidSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws {
        try self.serverDidReceiveHandshakeMessage(message)
    }
    
    func didSendChangeCipherSpec() throws {
        try self.serverDidReceiveChangeCipherSpec()
    }

    func didReceiveChangeCipherSpec() throws {
        try self.serverDidReceiveChangeCipherSpec()
    }
    
    func didConnect() throws {
        try self.serverDidConnect()
    }
    
    func didReceiveAlert(_ alert : TLSAlertMessage) {
        self.serverDidReceiveAlert(alert)
    }
    
    func shouldContinueHandshake(with message : TLSHandshakeMessage) -> Bool {
        return self.serverShouldContinueHandshake(with: message)
    }
}

