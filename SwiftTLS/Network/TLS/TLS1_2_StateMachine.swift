//
//  TLS1_2.ConnectionStateMachine.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 25.02.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

protocol TLS1_2_ConnectionStateMachine : TLSConnectionStateMachine
{
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    func didReceiveChangeCipherSpec() throws
}
