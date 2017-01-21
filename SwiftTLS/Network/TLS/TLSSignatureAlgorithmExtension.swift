//
//  TLSSignatureAlgorithmExtension.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 27.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLSSignatureAlgorithmExtension : TLSHelloExtension
{
    var extensionType : TLSHelloExtensionType {
        get {
            return .signatureAlgorithms
        }
    }
    
    var signatureAlgorithms: [TLSSignatureAlgorithm]
    
    init(signatureAlgorithms: [TLSSignatureAlgorithm])
    {
        self.signatureAlgorithms = signatureAlgorithms
    }
    
    init?(inputStream: InputStreamType) {
        self.signatureAlgorithms = []
        
        guard
            let rawSignatureAlgorithms : [UInt16] = inputStream.read16()
            else {
                return nil
        }
        
        for rawAlgorithm in rawSignatureAlgorithms
        {
            if let algorithm = TLSSignatureAlgorithm(rawValue: rawAlgorithm) {
                self.signatureAlgorithms.append(algorithm)
            }
            else {
                return nil
            }
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        let data = DataBuffer()
        for algorithm in self.signatureAlgorithms {
            data.write(algorithm.rawValue)
        }
        
        let extensionsData = data.buffer
        let extensionsLength = extensionsData.count
        
        target.write(self.extensionType.rawValue)
        target.write(UInt16(extensionsData.count + 2))
        target.write(UInt16(extensionsLength))
        target.write(extensionsData)
    }
    
}
