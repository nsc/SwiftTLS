//
//  TLS1_3.BaseProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLS1_3 {}

extension TLS1_3 {
    class BaseProtocol {
        internal weak var connection: TLSConnection!
        
        init(connection: TLSConnection)
        {
            self.connection = connection
        }
        
        func sendCertificate() throws
        {
            let certificates = self.connection.configuration.identity!.certificateChain
            let certificateMessage = TLSCertificateMessage(certificates: certificates)
            
            try self.connection.sendHandshakeMessage(certificateMessage);
        }
        
        func sendFinished() throws
        {
            let verifyData = self.connection.verifyDataForFinishedMessage(isClient: self.connection.isClient)
            if self.connection.securityParameters.isUsingSecureRenegotiation {
                self.connection.saveVerifyDataForSecureRenegotiation(data: verifyData, forClient: self.connection.isClient)
            }
            try self.connection.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
        }
    }
}
