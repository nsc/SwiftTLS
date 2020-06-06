//
//  TLS1_3.RecordLayer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 03.02.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    static let ivLabel  = [UInt8]("iv".utf8)
    static let keyLabel = [UInt8]("key".utf8)

    class RecordLayer : TLSBaseRecordLayer
    {
        typealias SequenceNumberType = UInt64
        
        var recordLayer: RecordLayer {
            return connection!.recordLayer as! RecordLayer
        }

        var protocolHandler: BaseProtocol {
            return connection!.protocolHandler as! BaseProtocol
        }
        
        struct EncryptionParameters {
            var cipherSuiteDecriptor: CipherSuiteDescriptor
            var key: [UInt8]
            var iv: [UInt8]
            var sequenceNumber: SequenceNumberType = 0
            
            var blockSize: Int {
                return cipherSuiteDecriptor.bulkCipherAlgorithm.blockSize
            }
            
            var currentIV: [UInt8] {
                // XOR the IV with the sequence number as of RFC 8446 section 5.3 Per-Record Nonce
                let sequenceNumberSize = MemoryLayout<SequenceNumberType>.size
                let ivLeftPart  = [UInt8](self.iv[0 ..< self.iv.count - sequenceNumberSize])
                let ivRightPart = [UInt8](self.iv[self.iv.count - sequenceNumberSize ..< self.iv.count])
                let iv : [UInt8] = ivLeftPart + (ivRightPart ^ sequenceNumber.bigEndianBytes)
                
                return iv
            }
        }
        
        var readEncryptionParameters: EncryptionParameters?
        var writeEncryptionParameters: EncryptionParameters?

        private var encryptor : BlockCipher!
        private var decryptor : BlockCipher!

        private func newBlockCipherAndEncryptionParameters(withTrafficSecret trafficSecret: [UInt8], forReading isReading: Bool) -> (blockCipher: BlockCipher, encryptionParameters: EncryptionParameters) {
            guard let cipherSuite = connection?.cipherSuite else {
                fatalError("changeTrafficKey called with no cipherSuite selected")
            }
            
            guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
                else {
                    fatalError("Unsupported cipher suite \(cipherSuite)")
            }
            
            guard let blockCipherMode = cipherSuiteDescriptor.blockCipherMode else {
                fatalError("changeTrafficKeys called with no cipherMode selected")
            }
            
            let ivSize = cipherSuiteDescriptor.fixedIVLength
            let keySize = cipherSuiteDescriptor.bulkCipherAlgorithm.keySize
            
            // calculate traffic keys and IVs as of RFC 8446 Section 7.3 Traffic Key Calculation
            let key = protocolHandler.HKDF_Expand_Label(secret: trafficSecret, label: keyLabel,  hashValue: [], outputLength: keySize)
            let iv  = protocolHandler.HKDF_Expand_Label(secret: trafficSecret, label: ivLabel, hashValue: [], outputLength: ivSize)
            
            let encryptionParameters = EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor,
                                                            key: key,
                                                            iv: iv,
                                                            sequenceNumber: 0)
            
            let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
            let cryptor: BlockCipher
            if isReading {
//                log("\(self.connection!.isClient ? "Client" : "Server"): change read key to \(hex(key))")
                cryptor  = BlockCipher.decryptionBlockCipher(cipherAlgorithm, mode: blockCipherMode, key: key)!
            } else {
//                log("\(self.connection!.isClient ? "Client" : "Server"): change write key to \(hex(key))")
                cryptor  = BlockCipher.encryptionBlockCipher(cipherAlgorithm, mode: blockCipherMode, key: key)!
            }
                
            return (cryptor, encryptionParameters)
        }
        
        func changeWriteKeys(withTrafficSecret trafficSecret: [UInt8]) {
            let (blockCipher, encryptionParameters) = self.newBlockCipherAndEncryptionParameters(withTrafficSecret: trafficSecret, forReading: false)
            
            self.writeEncryptionParameters = encryptionParameters
            self.encryptor = blockCipher
        }

        func changeReadKeys(withTrafficSecret trafficSecret: [UInt8]) {
            let (blockCipher, encryptionParameters) = self.newBlockCipherAndEncryptionParameters(withTrafficSecret: trafficSecret, forReading: true)

            self.readEncryptionParameters = encryptionParameters
            self.decryptor = blockCipher
        }
        
        func changeKeys(withClientTrafficSecret clientTrafficSecret: [UInt8], serverTrafficSecret: [UInt8]) {
            if self.isClient {
                changeWriteKeys(withTrafficSecret: clientTrafficSecret)
                changeReadKeys(withTrafficSecret: serverTrafficSecret)
            }
            else {
                changeWriteKeys(withTrafficSecret: serverTrafficSecret)
                changeReadKeys(withTrafficSecret: clientTrafficSecret)
            }
        }
        
        override func readRecordBody(count: Int) throws -> [UInt8] {
            guard count > 0 && count <= (1 << 14) + 256 else {
                try connection!.abortHandshake(with: .recordOverflow)
            }
            
            return try super.readRecordBody(count: count)
        }
        
        override func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8] {
            if let encryptionParameters = self.writeEncryptionParameters {
                
                let paddingLength = 12
                let padding = [UInt8](repeating: 0, count: paddingLength)
                let plainTextRecordData = data + [contentType.rawValue] + padding
                var cipherText : [UInt8]
                
                let cipherSuiteDescriptor = encryptionParameters.cipherSuiteDecriptor

                var authDataBuffer: [UInt8] = []
                authDataBuffer.write(ContentType.applicationData.rawValue)
                authDataBuffer.write(TLSProtocolVersion.v1_2.rawValue)
                authDataBuffer.write(UInt16(plainTextRecordData.count + cipherSuiteDescriptor.authTagSize))

                let additionalData = authDataBuffer

                if let b = self.encrypt(plainTextRecordData, authData: additionalData, key: encryptionParameters.key, IV: encryptionParameters.currentIV) {
                    cipherText = b + self.encryptor.authTag!
                }
                else {
                    throw TLSError.error("Could not encrypt")
                }
                
                self.writeEncryptionParameters!.sequenceNumber += 1
                
                let record = TLSRecord(contentType: .applicationData, protocolVersion: .v1_2, body: cipherText)
                return [UInt8](record)
            }
            else {
                // no security parameters have been negotiated yet
                let record = TLSRecord(contentType: contentType, protocolVersion: .v1_2, body: data)
                return [UInt8](record)
            }
        }

        override func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8]) {
            guard let encryptionParameters = self.readEncryptionParameters else {
                return (contentType, recordData)
            }
            
            // To increase compatibility with strange middleboxes TLS 1.3 allows for changeCipherSpec to be sent
            // at any time during the handshake after the first ClientHello. Ignore it here (see RFC section about
            // the Record Protocol and about Middlebox Compatibility Mode)
            if self.protocolVersion == .v1_3 &&
                contentType == .changeCipherSpec &&
                recordData == [1] {
            
                return (contentType, recordData)
            }
        
            let cipherSuiteDescriptor = encryptionParameters.cipherSuiteDecriptor

//            log("recordData.count = \(recordData.count) / auth tag size = \(cipherSuiteDescriptor.authTagSize)")
            guard recordData.count >= cipherSuiteDescriptor.authTagSize else {
                // FIXME: I haven't found anything in the RFC about how to handle this case. What is the correct alert to send here?
                try connection!.abortHandshake(with: .unexpectedMessage)
            }
            
            // FIXME: The server has crashed in the next line with an invalid index
            let cipherText = [UInt8](recordData[0..<(recordData.count - cipherSuiteDescriptor.authTagSize)])
            let authTag    = [UInt8](recordData[(recordData.count - cipherSuiteDescriptor.authTagSize)..<recordData.count])
            
            var additionalData: [UInt8] = []
            additionalData.write(ContentType.applicationData.rawValue)
            additionalData.write(TLSProtocolVersion.v1_2.rawValue)
            additionalData.write(UInt16(cipherText.count + cipherSuiteDescriptor.authTagSize))
            
            if let messageData = self.decrypt(cipherText, authData: additionalData, key: encryptionParameters.key, IV: encryptionParameters.currentIV) {
            
                if authTag != self.decryptor.authTag! {
                    // FIXME: Check if this actually *is* the correct alert
                    throw TLSError.alert(alert: .badRecordMAC, alertLevel: .fatal)
                }
                
                self.readEncryptionParameters!.sequenceNumber += 1
                
                // check padding by searching for the first non-zero byte backwards
                var index = messageData.count - 1
                while index >= 0 && messageData[index] == 0 {
                    index -= 1
                }
                
                guard index >= 0 else {
                    throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
                }
                
                if let contentType = ContentType(rawValue:messageData[index]) {
                    if index == 0 && contentType != .applicationData {
                        throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
                    }
                    
                    return (contentType, [UInt8](messageData[0..<index]))
                }
                else {
                    throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
                }
            }
            else {
                // FIXME: Check if this actually *is* the correct alert
                throw TLSError.alert(alert: .badRecordMAC, alertLevel: .fatal)
            }
        }
        
        private func encrypt(_ data : [UInt8], authData: [UInt8]?, key : [UInt8], IV : [UInt8]) -> [UInt8]?
        {
            return self.encryptor.update(data: data, authData: authData, key: key, IV: IV)
        }
        
        private func decrypt(_ data : [UInt8], authData: [UInt8]?, key : [UInt8], IV : [UInt8]) -> [UInt8]?
        {
            return self.decryptor.update(data: data, authData: authData, key: key, IV: IV)
        }
    
        override func readMessage() throws -> TLSMessage?
        {
            // When we are a server still in the handshake phase and we have rejected early data, we need to try to decrypt incoming packets
            // with our handshake keys until we can actually decrypt it.
            // Since early data is encrypted with early data keys, this will fail until the client sends its Finished message.
            guard let serverProtocolHandler = ((self.connection as? TLSServer)?.serverProtocolHandler as? ServerProtocol),
                serverProtocolHandler.server.stateMachine!.state != .connected,
                case .rejected = serverProtocolHandler.serverHandshakeState.serverEarlyDataState
            else {
                return try super.readMessage()
            }
            
            let message: TLSMessage?
            do {
                message = try super.readMessage()
            } catch TLSError.alert(let alert, _) where alert == .badRecordMAC {
                // ignore message and read the next one
                return try readMessage()
            }
            
            return message
        }
    }

}
