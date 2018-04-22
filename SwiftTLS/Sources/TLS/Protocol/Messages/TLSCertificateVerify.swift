//
//  TLSCertificateVerify.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 19.02.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class TLSCertificateVerify : TLSHandshakeMessage
    {
        let algorithm: TLSSignatureScheme
        let signature: [UInt8]
        
        init(algorithm: TLSSignatureScheme, signature: [UInt8])
        {
            self.algorithm = algorithm
            self.signature = signature
            
            super.init(type: .handshake(.certificateVerify))
        }
        
        required init?(inputStream : InputStreamType, context: TLSConnection)
        {
            guard let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.certificateVerify else {
                return nil
            }
            
            guard let rawSignatureScheme: UInt16 = inputStream.read() else {
                return nil
            }
            
            guard let signatureScheme = TLSSignatureScheme(rawValue: rawSignatureScheme) else {
                log("Error: Unknown signature scheme \(String(format: "0x%hs", rawSignatureScheme))")
                return nil
            }
            log("Signature scheme \(String(format: "0x%04hx", rawSignatureScheme))")
            
            guard let signature: [UInt8] = inputStream.read16() else {
                return nil
            }
            
            guard bodyLength == (2 + 2 + signature.count) else {
                log("Error: excess data in CertificateVerify message")
                return nil
            }
            
            self.algorithm = signatureScheme
            self.signature = signature
            
            super.init(type: .handshake(.certificateVerify))
        }
        
        override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
        {
            var data: [UInt8] = []
            
            data.write(self.algorithm.rawValue)
            data.write16(signature)
            
            self.writeHeader(type: .certificateVerify, bodyLength: data.count, target: &target)
            target.write(data)
        }
    }
}
