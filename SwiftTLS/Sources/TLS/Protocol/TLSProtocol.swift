//
//  TLSProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

protocol TLSProtocol
{
    func handleFinished(_ finished: TLSFinished) throws
    func handleCertificate(_ certificate: TLSCertificateMessage)
    
    // All TLS protocol messages that are not shared by all supported TLS protocols
    // must be handled by handleMessage.
    // As of TLS 1.3 these are:
    // - ServerHelloDone
    // - ClientKeyExchange
    // - ServerKeyExchange
    // - ChangeCipherSpec
    // - EncryptedExtensions
    // - CertificateVerify
    // - HelloRetryRequest
    // - NewSessionTicket
    func handleMessage(_ message : TLSMessage) throws
    
    func sendCertificate() throws
    func sendFinished() throws
    
    var connectionInfo: String { get }
}

protocol TLSClientProtocol : TLSProtocol
{
    func sendClientHello() throws
    func handleServerHello(_ serverHello: TLSServerHello) throws
}

protocol TLSServerProtocol : TLSProtocol
{
    func sendServerHello(for clientHello: TLSClientHello) throws
    func handleClientHello(_ clientHello: TLSClientHello) throws
}
