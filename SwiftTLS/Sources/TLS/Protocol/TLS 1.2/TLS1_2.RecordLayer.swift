//
//  TLSRecordLayer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

extension TLS1_2 {
    
    class EncryptionParameters {
        var hmac : MACAlgorithm
        var bulkCipherAlgorithm : CipherAlgorithm
        var cipherType : CipherType
        var blockCipherMode : BlockCipherMode?
        var MACKey  : [UInt8]
        var bulkKey : [UInt8]
        var blockLength : Int
        var fixedIVLength : Int
        var recordIVLength : Int
        var fixedIV      : [UInt8]
        var sequenceNumber : UInt64
        
        init(hmac: MACAlgorithm,
             MACKey: [UInt8],
             bulkCipherAlgorithm: CipherAlgorithm,
             blockCipherMode: BlockCipherMode? = nil,
             bulkKey: [UInt8],
             blockLength: Int,
             fixedIVLength: Int,
             recordIVLength: Int,
             fixedIV: [UInt8],
             sequenceNumber: UInt64 = UInt64(0))
        {
            self.hmac = hmac
            self.bulkCipherAlgorithm = bulkCipherAlgorithm
            self.blockCipherMode = blockCipherMode
            
            if let blockCipherMode = self.blockCipherMode {
                switch blockCipherMode {
                case .cbc:
                    self.cipherType = .block
                case .gcm:
                    self.cipherType = .aead
                }
            }
            else {
                self.cipherType = .stream
            }
            
            self.MACKey = MACKey
            self.bulkKey = bulkKey
            self.blockLength = blockLength
            self.fixedIVLength = fixedIVLength
            self.recordIVLength = recordIVLength
            self.fixedIV = fixedIV
            self.sequenceNumber = sequenceNumber
        }
        
    }
    
    public class RecordLayer : TLSBaseRecordLayer
    {
        private var currentReadEncryptionParameters  : EncryptionParameters? {
            didSet {
                self.decryptor = nil
            }
        }
        private var pendingReadEncryptionParameters  : EncryptionParameters?
        private var currentWriteEncryptionParameters : EncryptionParameters? {
            didSet {
                self.encryptor = nil
            }
        }
        
        private var pendingWriteEncryptionParameters : EncryptionParameters?
        
        var pendingSecurityParameters  : TLSSecurityParameters? {
            didSet {
                if let s = pendingSecurityParameters, let hmac = s.hmac {
                    
                    let hmacSize = s.cipherType == .aead ? 0 : hmac.size
                    let numberOfKeyMaterialBytes = 2 * (hmacSize + s.encodeKeyLength + s.fixedIVLength)
                    let protocolHandler = self.connection!.protocolHandler as! TLS1_2.BaseProtocol
                    let keyBlock = protocolHandler.PRF(secret: s.masterSecret!, label: TLSKeyExpansionLabel, seed: s.serverRandom! + s.clientRandom!, outputLength: numberOfKeyMaterialBytes)
                    
                    var index = 0
                    let clientWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
                    index += hmacSize
                    
                    let serverWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
                    index += hmacSize
                    
                    let clientWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
                    index += s.encodeKeyLength
                    
                    let serverWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
                    index += s.encodeKeyLength
                    
                    let clientWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
                    index += s.fixedIVLength
                    
                    let serverWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
                    index += s.fixedIVLength
                    
                    var readEncryptionParameters  : EncryptionParameters
                    var writeEncryptionParameters : EncryptionParameters
                    
                    if self.isClient {
                        readEncryptionParameters  = EncryptionParameters(hmac: hmac,
                                                                         MACKey: serverWriteMACKey,
                                                                         bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                                                                         blockCipherMode: s.blockCipherMode,
                                                                         bulkKey: serverWriteKey,
                                                                         blockLength: s.blockLength,
                                                                         fixedIVLength: s.fixedIVLength,
                                                                         recordIVLength: s.recordIVLength,
                                                                         fixedIV: serverWriteIV)
                        
                        writeEncryptionParameters = EncryptionParameters(hmac: hmac,
                                                                         MACKey: clientWriteMACKey,
                                                                         bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                                                                         blockCipherMode: s.blockCipherMode,
                                                                         bulkKey: clientWriteKey,
                                                                         blockLength: s.blockLength,
                                                                         fixedIVLength: s.fixedIVLength,
                                                                         recordIVLength: s.recordIVLength,
                                                                         fixedIV: clientWriteIV)
                    }
                    else {
                        readEncryptionParameters  = EncryptionParameters(hmac: hmac,
                                                                         MACKey: clientWriteMACKey,
                                                                         bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                                                                         blockCipherMode: s.blockCipherMode,
                                                                         bulkKey: clientWriteKey,
                                                                         blockLength: s.blockLength,
                                                                         fixedIVLength: s.fixedIVLength,
                                                                         recordIVLength: s.recordIVLength,
                                                                         fixedIV: clientWriteIV)
                        
                        writeEncryptionParameters = EncryptionParameters(hmac: hmac,
                                                                         MACKey: serverWriteMACKey,
                                                                         bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                                                                         blockCipherMode: s.blockCipherMode,
                                                                         bulkKey: serverWriteKey,
                                                                         blockLength: s.blockLength,
                                                                         fixedIVLength: s.fixedIVLength,
                                                                         recordIVLength: s.recordIVLength,
                                                                         fixedIV: serverWriteIV)
                    }
                    
                    self.pendingWriteEncryptionParameters = writeEncryptionParameters
                    self.pendingReadEncryptionParameters  = readEncryptionParameters
                }
            }
        }
        
        private var encryptor : BlockCipher!
        private var decryptor : BlockCipher!
        
        func activateReadEncryptionParameters()
        {
            self.currentReadEncryptionParameters = self.pendingReadEncryptionParameters
            self.pendingReadEncryptionParameters = nil
        }
        
        func activateWriteEncryptionParameters()
        {
            self.currentWriteEncryptionParameters = self.pendingWriteEncryptionParameters
            self.pendingWriteEncryptionParameters = nil
        }
        
        override func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8]
        {
            if let encryptionParameters = self.currentWriteEncryptionParameters {
                let secret = encryptionParameters.MACKey
                
                let isAEAD = (encryptionParameters.cipherType == .aead)
                
                let IV : [UInt8]
                let recordIV : [UInt8]
                switch self.protocolVersion
                {
                case TLSProtocolVersion.v1_0:
                    IV = encryptionParameters.fixedIV
                    recordIV = IV
                    
                case TLSProtocolVersion.v1_1:
                    IV = TLSRandomBytes(count: encryptionParameters.recordIVLength)
                    recordIV = IV
                    
                case TLSProtocolVersion.v1_2:
                    recordIV = TLSRandomBytes(count: encryptionParameters.recordIVLength)
                    IV = (isAEAD ? encryptionParameters.fixedIV : []) + recordIV
                    
                default:
                    fatalError("Unsupported TLS version \(self.protocolVersion)")
                }
                
                
                let MAC : [UInt8]
                if isAEAD {
                    MAC = []
                }
                else {
                    guard let mac = calculateMessageMAC(secret: secret, contentType: contentType, data: data, isRead: false) else { throw TLSError.error("Could not MAC")}
                    
                    MAC = mac
                }
                
                var plainTextRecordData = data + MAC
                let blockLength = encryptionParameters.blockLength
                if !isAEAD && blockLength > 0 {
                    let paddingLength = blockLength - ((plainTextRecordData.count) % blockLength)
                    if paddingLength != 0 {
                        let padding = [UInt8](repeating: UInt8(paddingLength - 1), count: paddingLength)
                        
                        plainTextRecordData.append(contentsOf: padding)
                    }
                }
                
                var cipherText : [UInt8]
                let macHeader = isAEAD ? self.MACHeader(forContentType: contentType, dataLength: plainTextRecordData.count, isRead: false) : []
                if let b = encrypt(plainTextRecordData, authData: macHeader, key: encryptionParameters.bulkKey, IV: IV) {
                    cipherText = b
                    if self.protocolVersion >= TLSProtocolVersion.v1_1 {
                        if let cipherMode = encryptionParameters.blockCipherMode, cipherMode == .gcm {
                            cipherText = cipherText + self.encryptor.authTag!
                        }
                        cipherText = recordIV + cipherText
                    }
                }
                else {
                    throw TLSError.error("Could not encrypt")
                }
                
                encryptionParameters.sequenceNumber += 1
                
                let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: cipherText)
                return [UInt8](record)
            }
            else {
                // no security parameters have been negotiated yet
                let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: data)
                return [UInt8](record)
            }
        }
        
        override func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8]) {
            if let encryptionParameters = self.currentReadEncryptionParameters {
                if let decryptedMessage = self.decryptAndVerifyMAC(contentType: contentType, data: recordData) {
                    encryptionParameters.sequenceNumber += 1

                    return (contentType, decryptedMessage)
                }
                else {
                    throw TLSError.alert(alert: .badRecordMAC, alertLevel: .fatal)
                }
            }

            return (contentType, recordData)
        }
        
        private func MACHeader(forContentType contentType: ContentType, dataLength: Int, isRead: Bool) -> [UInt8]? {
            guard let encryptionParameters = isRead ? self.currentReadEncryptionParameters : self.currentWriteEncryptionParameters else { return nil }
            
            var macData: [UInt8] = []
            macData.write(encryptionParameters.sequenceNumber)
            macData.write(contentType.rawValue)
            macData.write(self.protocolVersion.rawValue)
            macData.write(UInt16(dataLength))
            
            return macData
        }
        
        private func calculateMessageMAC(secret: [UInt8], contentType : ContentType, data : [UInt8], isRead : Bool) -> [UInt8]?
        {
            guard let MACHeader = self.MACHeader(forContentType: contentType, dataLength: data.count, isRead: isRead) else { return nil }
            
            return self.calculateMAC(secret: secret, data: MACHeader + data, isRead: isRead)
        }
        
        private func calculateMAC(secret : [UInt8], data : [UInt8], isRead : Bool) -> [UInt8]?
        {
            var HMAC : (_ secret : [UInt8], _ data : [UInt8]) -> [UInt8]
            if let algorithm = isRead ? self.currentReadEncryptionParameters?.hmac : self.currentWriteEncryptionParameters?.hmac {
                switch (algorithm)
                {
                case .hmac_md5:
                    HMAC = HMAC_MD5
                    
                case .hmac_sha1:
                    HMAC = HMAC_SHA1
                    
                case .hmac_sha256:
                    HMAC = HMAC_SHA256
                    
                case .hmac_sha384:
                    HMAC = HMAC_SHA384
                    
                case .hmac_sha512:
                    HMAC = HMAC_SHA512
                }
            }
            else {
                return nil
            }
            
            return HMAC(secret, data)
        }
        
        private func encrypt(_ data : [UInt8], authData: [UInt8]?, key : [UInt8], IV : [UInt8]) -> [UInt8]?
        {
            let encryptionParameters = self.currentWriteEncryptionParameters!
            
            if self.encryptor == nil
            {
                self.encryptor = BlockCipher.encryptionBlockCipher(encryptionParameters.bulkCipherAlgorithm, mode: encryptionParameters.blockCipherMode!, key: key)
            }
            
            if self.protocolVersion >= TLSProtocolVersion.v1_1 {
                return self.encryptor.update(data: data, authData: authData, key: key, IV: IV)
            }
            else {
                return self.encryptor.update(data: data, authData: authData, key: key, IV: nil)
            }
        }
        
        private func decrypt(_ data : [UInt8], authData: [UInt8]?, key : [UInt8], IV : [UInt8]) -> [UInt8]?
        {
            let encryptionParameters = self.currentReadEncryptionParameters!
            
            if self.decryptor == nil
            {
                self.decryptor = BlockCipher.decryptionBlockCipher(encryptionParameters.bulkCipherAlgorithm, mode: encryptionParameters.blockCipherMode!, key: key)
            }
            
            if self.protocolVersion >= TLSProtocolVersion.v1_1 {
                return self.decryptor.update(data: data, authData: authData, key: key, IV: IV)
            }
            else {
                return self.decryptor.update(data: data, authData: authData, key: key, IV: nil)
            }
        }
        
        private func decryptAndVerifyMAC(contentType : ContentType, data : [UInt8]) -> [UInt8]?
        {
            if let encryptionParameters = self.currentReadEncryptionParameters
            {
                let isAEAD = (encryptionParameters.cipherType == .aead)
                
                let IV : [UInt8]
                let cipherText : [UInt8]
                var authTag : [UInt8]? = nil
                switch self.protocolVersion
                {
                case TLSProtocolVersion.v1_0:
                    IV = encryptionParameters.fixedIV
                    cipherText = data
                    
                case TLSProtocolVersion.v1_1:
                    IV = [UInt8](data[0..<encryptionParameters.recordIVLength])
                    cipherText = [UInt8](data[encryptionParameters.recordIVLength..<data.count])
                    
                case TLSProtocolVersion.v1_2:
                    IV = (isAEAD ? encryptionParameters.fixedIV : []) + [UInt8](data[0..<encryptionParameters.recordIVLength])
                    if let cipherMode = encryptionParameters.blockCipherMode, cipherMode == .gcm {
                        cipherText = [UInt8](data[encryptionParameters.recordIVLength..<(data.count - encryptionParameters.blockLength)])
                        authTag = [UInt8](data[(data.count - encryptionParameters.blockLength)..<data.count])
                    }
                    else {
                        cipherText = [UInt8](data[encryptionParameters.recordIVLength..<data.count])
                    }
                    
                default:
                    fatalError("Unsupported TLS version \(self.protocolVersion)")
                }
                
                let macHeader = isAEAD ? self.MACHeader(forContentType: contentType, dataLength: data.count - encryptionParameters.recordIVLength - encryptionParameters.blockLength, isRead: true) : []
                if let message = decrypt(cipherText, authData: macHeader, key: encryptionParameters.bulkKey, IV: IV) {
                    
                    if isAEAD {
                        if let authTag = authTag {
                            if authTag != self.decryptor.authTag! {
                                // Decryption error. The authentication tag doesn't match
                                return nil
                            }
                        }
                        return message
                    }
                    
                    let hmacLength = encryptionParameters.hmac.size
                    var messageLength = message.count - hmacLength
                    
                    if encryptionParameters.blockLength > 0 {
                        let padding = message.last!
                        let paddingLength = Int(padding) + 1
                        var paddingIsCorrect = (paddingLength < message.count)
                        paddingIsCorrect = paddingIsCorrect && (message[(message.count - paddingLength) ..< message.count].filter({$0 != padding}).count == 0)
                        if !paddingIsCorrect {
                            log("Error: could not decrypt message")
                            return nil
                        }
                        messageLength -= paddingLength
                    }
                    
                    let messageContent = [UInt8](message[0..<messageLength])
                    
                    let MAC = [UInt8](message[messageLength..<messageLength + hmacLength])
                    
                    let messageMAC = self.calculateMessageMAC(secret: encryptionParameters.MACKey, contentType: contentType, data: messageContent, isRead: true)
                    
                    if let messageMAC = messageMAC, MAC == messageMAC {
                        return messageContent
                    }
                    else {
                        log("Error: MAC doesn't match")
                    }
                }
            }
            
            return nil
        }
    }
}
