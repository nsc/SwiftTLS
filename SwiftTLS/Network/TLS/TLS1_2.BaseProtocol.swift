//
//  TLS1_2.BaseProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_2 {
    class BaseProtocol
    {
        internal weak var connection: TLSConnection!
        
        init(connection: TLSConnection)
        {
            self.connection = connection
        }
        
        func sendChangeCipherSpec() throws
        {
            let message = TLSChangeCipherSpec()
            try self.connection.sendMessage(message)
            self.connection.recordLayer.activateWriteEncryptionParameters()
            try self.connection.stateMachine?.didSendChangeCipherSpec()
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
