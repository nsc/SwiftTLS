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
            var readKey: [UInt8]
            var readIV:  [UInt8]
            var writeKey: [UInt8]
            var writeIV:  [UInt8]
            var readSequenceNumber: SequenceNumberType = 0
            var writeSequenceNumber: SequenceNumberType = 0
            
            var blockSize: Int {
                return cipherSuiteDecriptor.bulkCipherAlgorithm.blockSize
            }
            
            var currentWriteIV: [UInt8] {
                // XOR the write IV with the sequence number as of RFC???? section 5.3 Per-Record Nonce
                let sequenceNumberSize = MemoryLayout<SequenceNumberType>.size
                let writeIVLeftPart = [UInt8](writeIV[0..<writeIV.count - sequenceNumberSize])
                let writeIVRightPart = [UInt8](writeIV[writeIV.count - sequenceNumberSize..<writeIV.count])
                let IV : [UInt8] = writeIVLeftPart + (writeIVRightPart ^ writeSequenceNumber.bigEndianByteArray())
                
                return IV
            }

            var currentReadIV: [UInt8] {
                // XOR the read IV with the sequence number as of RFC???? section 5.3 Per-Record Nonce
                let sequenceNumberSize = MemoryLayout<SequenceNumberType>.size
                let readIVLeftPart = [UInt8](readIV[0..<readIV.count - sequenceNumberSize])
                let readIVRightPart = [UInt8](readIV[readIV.count - sequenceNumberSize..<readIV.count])
                let IV : [UInt8] = readIVLeftPart + (readIVRightPart ^ readSequenceNumber.bigEndianByteArray())
                
                return IV
            }
        }
        
        var encryptionParameters: EncryptionParameters?

        private var encryptor : BlockCipher!
        private var decryptor : BlockCipher!

        func changeTrafficSecrets(clientTrafficSecret: [UInt8], serverTrafficSecret: [UInt8]) {
            guard let cipherSuite = connection?.cipherSuite else {
                fatalError("changeTrafficKeys called with no cipherSuite selected")
            }
            
            guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
                else {
                    fatalError("Unsupported cipher suite \(cipherSuite)")
            }

            guard let cipherMode = cipherSuiteDescriptor.blockCipherMode else {
                fatalError("changeTrafficKeys called with no cipherMode selected")
            }

            let ivSize = cipherSuiteDescriptor.fixedIVLength
            let keySize = cipherSuiteDescriptor.bulkCipherAlgorithm.keySize
            
            
            // calculate traffic keys and IVs as of RFC???? Section 7.3 Traffic Key Calculation
            let clientWriteKey = protocolHandler.HKDF_Expand_Label(secret: clientTrafficSecret, label: keyLabel,  hashValue: [], outputLength: keySize)
            let clientWriteIV  = protocolHandler.HKDF_Expand_Label(secret: clientTrafficSecret, label: ivLabel, hashValue: [], outputLength: ivSize)
            let serverWriteKey = protocolHandler.HKDF_Expand_Label(secret: serverTrafficSecret, label: keyLabel,  hashValue: [], outputLength: keySize)
            let serverWriteIV  = protocolHandler.HKDF_Expand_Label(secret: serverTrafficSecret, label: ivLabel, hashValue: [], outputLength: ivSize)
            
            
            var encryptionParameters : EncryptionParameters
            if self.isClient {
                encryptionParameters = EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor,
                                                            readKey: serverWriteKey,
                                                            readIV: serverWriteIV,
                                                            writeKey: clientWriteKey,
                                                            writeIV: clientWriteIV,
                                                            readSequenceNumber: 0,
                                                            writeSequenceNumber: 0)
            }
            else {
                encryptionParameters = EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor,
                                                            readKey: clientWriteKey,
                                                            readIV: clientWriteIV,
                                                            writeKey: serverWriteKey,
                                                            writeIV: serverWriteIV,
                                                            readSequenceNumber: 0,
                                                            writeSequenceNumber: 0)
            }
            
            self.encryptionParameters = encryptionParameters
            
            let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
            self.encryptor = BlockCipher.encryptionBlockCipher(cipherAlgorithm, mode: cipherMode, key: encryptionParameters.writeKey, IV: [])
            self.decryptor = BlockCipher.decryptionBlockCipher(cipherAlgorithm, mode: cipherMode, key: encryptionParameters.readKey, IV: [])
        }
        
        override func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8]
        {
            if let encryptionParameters = self.encryptionParameters {
                
                let paddingLength = 12
                let padding = [UInt8](repeating: 0, count: paddingLength)
                let plainTextRecordData = data + [contentType.rawValue] + padding
                var cipherText : [UInt8]
                if let b = self.encrypt(plainTextRecordData, authData: nil, key: encryptionParameters.writeKey, IV: encryptionParameters.currentWriteIV) {
                    cipherText = b + self.encryptor.authTag!
                }
                else {
                    throw TLSError.error("Could not encrypt")
                }
                
                self.encryptionParameters!.writeSequenceNumber += 1
                
                let record = TLSRecord(contentType: .applicationData, protocolVersion: .v1_0, body: cipherText)
                return DataBuffer(record).buffer
            }
            else {
                // no security parameters have been negotiated yet
                let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: data)
                return DataBuffer(record).buffer
            }
        }

        override func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8]) {
            guard let encryptionParameters = self.encryptionParameters else {
                return (contentType, recordData)
            }
            
            let cipherSuiteDescriptor = encryptionParameters.cipherSuiteDecriptor

            let cipherText = [UInt8](recordData[0..<(recordData.count - cipherSuiteDescriptor.authTagSize)])
            let authTag    = [UInt8](recordData[(recordData.count - cipherSuiteDescriptor.authTagSize)..<recordData.count])
            
            if let message = self.decrypt(cipherText, authData: nil, key: encryptionParameters.readKey, IV: encryptionParameters.currentReadIV) {
            
                self.encryptionParameters!.readSequenceNumber += 1

                if authTag != self.decryptor.authTag! {
                    // FIXME: Check if this actually *is* the correct alert
                    throw TLSError.alert(alert: .badRecordMAC, alertLevel: .fatal)
                }
                
                // check padding by searching for the first non-zero byte backwards
                var index = message.count - 1
                while index >= 0 && message[index] == 0 {
                    index -= 1
                }
                
                guard index >= 0 else {
                    throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
                }
                
                if let contentType = ContentType(rawValue:message[index]) {
                    if index == 0 && contentType != .applicationData {
                        throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
                    }
                    
                    return (contentType, [UInt8](message[0..<index]))
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
    
    }

}
