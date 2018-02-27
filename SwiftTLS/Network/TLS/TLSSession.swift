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
    let masterSecret: [UInt8]

    init(sessionID: TLSSessionID, peerCertificate: X509.Certificate? = nil, cipherSpec: CipherSuite, masterSecret: [UInt8])
    {
        self.sessionID = sessionID
        self.peerCertificate = peerCertificate
        self.cipherSpec = cipherSpec
        self.masterSecret = masterSecret
    }
}

struct TLSSessionID : Streamable
{
    static let MaximumSessionIDLength = 32
    
    let sessionID : [UInt8]
    init(_ sessionID: [UInt8])
    {
        self.sessionID = sessionID
    }
    
    static func new() -> TLSSessionID {
        var sessionID = [UInt8](repeating: 0, count: MaximumSessionIDLength)
        arc4random_buf(&sessionID, sessionID.count)
        
        return TLSSessionID(sessionID)
    }
    
    init?(inputStream : InputStreamType)
    {
        if let length : UInt8 = inputStream.read() {
            if let sessionID : [UInt8] = inputStream.read(count: Int(length)) {
                self.sessionID = sessionID
                return
            }
        }
        
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        target.write(UInt8(sessionID.count))
        target.write(sessionID)
    }
}

extension TLSSessionID: Hashable {
    var hashValue: Int {
        return sessionID[0].hashValue ^ sessionID[1].hashValue ^ sessionID[2].hashValue ^ sessionID[3].hashValue
    }
}

func ==(lhs: TLSSessionID, rhs: TLSSessionID) -> Bool {
    return lhs.sessionID == rhs.sessionID
}

