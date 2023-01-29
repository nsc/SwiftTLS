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
    var connectionInfo: String { get }
}

protocol TLSClientProtocol : TLSProtocol
{
    func connect() async throws
    func handle(_ serverHello: TLSServerHello) async throws
}

protocol TLSServerProtocol : TLSProtocol
{
    func acceptConnection(withClientHello clientHello: TLSClientHello?) async throws
}
