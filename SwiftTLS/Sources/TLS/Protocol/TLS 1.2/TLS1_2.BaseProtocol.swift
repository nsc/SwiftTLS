//
//  TLS1_2.BaseProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 13.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLS1_2 {}

extension TLS1_2 {
    class BaseProtocol
    {
        internal weak var connection: TLSConnection!
        
        var securityParameters: TLSSecurityParameters
        var preMasterSecret: [UInt8]? = nil
        var isRenegotiatingSecurityParameters: Bool = false

        var recordLayer: RecordLayer {
            return connection!.recordLayer as! RecordLayer
        }
        
        init(connection: TLSConnection)
        {
            self.connection = connection
            self.securityParameters = TLSSecurityParameters()
        }
        
        func sendChangeCipherSpec() throws
        {
            let message = TLSChangeCipherSpec()
            try self.connection.sendMessage(message)
            self.recordLayer.activateWriteEncryptionParameters()
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
            let verifyData = self.verifyDataForFinishedMessage(isClient: self.connection.isClient)
            if self.securityParameters.isUsingSecureRenegotiation {
                self.saveVerifyDataForSecureRenegotiation(data: verifyData, forClient: self.connection.isClient)
            }
            try self.connection.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
        }
        
        func handleMessage(_ message: TLSMessage) throws
        {
            switch message.type {
            case .changeCipherSpec:
                self.recordLayer.activateReadEncryptionParameters()
                
            default:
                break
            }
        }
        
        func setPreMasterSecretAndCommitSecurityParameters(_ preMasterSecret : [UInt8], cipherSuite : CipherSuite? = nil)
        {
            var cipherSuite = cipherSuite
            if cipherSuite == nil {
                cipherSuite = connection.cipherSuite
            }
            
            self.connection.cipherSuite = cipherSuite
            self.preMasterSecret = preMasterSecret
            self.setPendingSecurityParametersForCipherSuite(cipherSuite!)
        }
        
        func setPendingSecurityParametersForCipherSuite(_ cipherSuite : CipherSuite)
        {
            guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
                else {
                    fatalError("Unsupported cipher suite \(cipherSuite)")
            }
            let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
            
            self.securityParameters.bulkCipherAlgorithm = cipherAlgorithm
            self.securityParameters.blockCipherMode     = cipherSuiteDescriptor.blockCipherMode
            self.securityParameters.cipherType          = cipherSuiteDescriptor.cipherType
            self.securityParameters.encodeKeyLength     = cipherAlgorithm.keySize
            self.securityParameters.blockLength         = cipherAlgorithm.blockSize
            self.securityParameters.fixedIVLength       = cipherSuiteDescriptor.fixedIVLength
            self.securityParameters.recordIVLength      = cipherSuiteDescriptor.recordIVLength
            self.securityParameters.hmac                = cipherSuiteDescriptor.hashAlgorithm.macAlgorithm
            
            var useConfiguredHashFunctionForPRF = self.securityParameters.blockCipherMode! == .gcm || cipherSuiteDescriptor.keyExchangeAlgorithm == .ecdhe
            
            switch cipherSuiteDescriptor.hashAlgorithm
            {
            case .sha256, .sha384:
                break
                
            default:
                useConfiguredHashFunctionForPRF = false
            }
            
            if !useConfiguredHashFunctionForPRF {
                // for non GCM or ECDHE cipher suites TLS 1.2 uses SHA256 for its PRF
                self.connection.hashAlgorithm = .sha256
            }
            else {
                switch cipherSuiteDescriptor.hashAlgorithm {
                case .sha256:
                    self.connection.hashAlgorithm = .sha256
                    
                case .sha384:
                    self.connection.hashAlgorithm = .sha384
                    
                default:
                    log("Error: cipher suite \(cipherSuite) has \(cipherSuiteDescriptor.hashAlgorithm)")
                    fatalError("AEAD cipher suites can only use SHA256 or SHA384")
                    break
                }
            }
            
            if let session = connection.currentSession {
                self.securityParameters.masterSecret = session.masterSecret
            }
            else {
                self.securityParameters.masterSecret = calculateMasterSecret()
            }
            self.recordLayer.pendingSecurityParameters = self.securityParameters
        }
        
        // Calculate master secret as described in RFC 2246, section 8.1, p. 46
        private func calculateMasterSecret() -> [UInt8]
        {
            return PRF(secret: self.preMasterSecret!, label: [UInt8]("master secret".utf8), seed: self.securityParameters.clientRandom! + self.securityParameters.serverRandom!, outputLength: 48)
        }
        
        func saveVerifyDataForSecureRenegotiation(data: [UInt8], forClient isClient: Bool)
        {
            if self.securityParameters.isUsingSecureRenegotiation {
                if isClient {
                    self.securityParameters.clientVerifyData = data
                }
                else {
                    self.securityParameters.serverVerifyData = data
                }
            }
        }
        
        func verifyFinishedMessage(_ finishedMessage : TLSFinished, isClient: Bool, saveForSecureRenegotiation: Bool) -> Bool
        {
            guard finishedMessage.verifyData == self.verifyDataForFinishedMessage(isClient: isClient) else {
                return false
            }
            
            if saveForSecureRenegotiation {
                saveVerifyDataForSecureRenegotiation(data: finishedMessage.verifyData, forClient: isClient)
            }
            
            return true
        }
        
//        func handleMessage(_ message: TLSMessage) throws
//        {
//            switch (message.type)
//            {
//            case .changeCipherSpec:
//                self.recordLayer.activateReadEncryptionParameters()
//                try self.connection.stateMachine?.didReceiveChangeCipherSpec()
//                try self.connection.receiveNextTLSMessage()
//                
//                break
//                
//            case .handshake:
//                let handshakeMessage = message as! TLSHandshakeMessage
//                if self.connection.stateMachine == nil || self.connection.stateMachine!.shouldContinueHandshake(with: handshakeMessage) {
//                    try self._didReceiveHandshakeMessage(handshakeMessage)
//                }
//                
//            case .alert:
//                let alert = message as! TLSAlertMessage
//                self.connection.stateMachine?.didReceiveAlert(alert)
//                if alert.alertLevel == .fatal {
//                    throw TLSError.alert(alert: alert.alert, alertLevel: alert.alertLevel)
//                }
//                
//                break
//                
//            case .applicationData:
//                break
//            }
//        }

        func verifyDataForFinishedMessage(isClient: Bool) -> [UInt8]
        {
            let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
            
            if connection.negotiatedProtocolVersion! < TLSProtocolVersion.v1_2 {
                let handshakeData = connection.handshakeMessageData

                let clientHandshakeMD5  = Hash_MD5(handshakeData)
                let clientHandshakeSHA1 = Hash_SHA1(handshakeData)
                
                let seed = clientHandshakeMD5 + clientHandshakeSHA1
                
                return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: seed, outputLength: 12)
            }
            else {
                let transcriptHash = connection.transcriptHash
                
                assert(self.securityParameters.masterSecret != nil)
                
                return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: transcriptHash, outputLength: 12)
            }
        }
        
        internal func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
        {
            if connection.negotiatedProtocolVersion! < TLSProtocolVersion.v1_2 {
                /// PRF function as defined in RFC 2246, section 5, p. 12
                
                let halfSecretLength = secret.count / 2
                let S1 : [UInt8]
                let S2 : [UInt8]
                if (secret.count % 2 == 0) {
                    S1 = [UInt8](secret[0..<halfSecretLength])
                    S2 = [UInt8](secret[halfSecretLength..<secret.count])
                }
                else {
                    S1 = [UInt8](secret[0..<halfSecretLength + 1])
                    S2 = [UInt8](secret[halfSecretLength..<secret.count])
                }
                
                assert(S1.count == S2.count)
                
                let md5data  = P_hash(HMAC_MD5,  secret: S1, seed: label + seed, outputLength: outputLength)
                let sha1data = P_hash(HMAC_SHA1, secret: S2, seed: label + seed, outputLength: outputLength)
                
                var output = [UInt8](repeating: 0, count: outputLength)
                for i in 0 ..< output.count
                {
                    output[i] = md5data[i] ^ sha1data[i]
                }
                
                return output
            }
            else {
                return P_hash(connection.hmac, secret: secret, seed: label + seed, outputLength: outputLength)
            }
        }

    }
}
