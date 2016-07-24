//
//  File.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 18.07.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSSession
{
    let sessionID: TLSSessionID
    let peerCertificate: X509.Certificate?
    let cipherSpec: CipherSuite
    let preMasterSecret: [UInt8]

    init(sessionID: TLSSessionID, peerCertificate: X509.Certificate? = nil, cipherSpec: CipherSuite, preMasterSecret: [UInt8])
    {
        self.sessionID = sessionID
        self.peerCertificate = peerCertificate
        self.cipherSpec = cipherSpec
        self.preMasterSecret = preMasterSecret
    }
}
