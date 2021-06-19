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
    func handle(_ finished: TLSFinished) throws -> TLSFinished
    func handle(_ certificate: TLSCertificateMessage)
    func sendCertificate() async throws
    func sendFinished() async throws
    
    var connectionInfo: String { get }
}

protocol TLSClientProtocol : TLSProtocol
{
    func connect() async throws
    func handle(_ serverHello: TLSServerHello) async throws
}

protocol TLSServerProtocol : TLSProtocol
{
    func acceptConnection() async throws
    @discardableResult
    func handle(_ clientHello: TLSClientHello) async throws -> TLSClientHello
}
