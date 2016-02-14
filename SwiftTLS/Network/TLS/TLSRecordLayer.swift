//
//  TLSRecordLayer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import CommonCrypto

let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

class EncryptionParameters {
    var hmacDescriptor : HMACDescriptor
    var bulkCipherAlgorithm : CipherAlgorithm
    var blockCipherMode : BlockCipherMode
    var MACKey  : [UInt8]
    var bulkKey : [UInt8]
    var blockLength : Int
    var IV      : [UInt8]
    var sequenceNumber : UInt64
    
    init(hmacDescriptor : HMACDescriptor, MACKey: [UInt8], bulkCipherAlgorithm: CipherAlgorithm, blockCipherMode: BlockCipherMode = .CBC, bulkKey: [UInt8], blockLength: Int, IV: [UInt8], sequenceNumber: UInt64 = UInt64(0))
    {
        self.hmacDescriptor = hmacDescriptor
        self.bulkCipherAlgorithm = bulkCipherAlgorithm
        self.blockCipherMode = blockCipherMode
        self.MACKey = MACKey
        self.bulkKey = bulkKey
        self.blockLength = blockLength
        self.IV = IV
        self.sequenceNumber = sequenceNumber
    }
    
}

public class TLSRecordLayer
{
    weak var dataProvider : TLSDataProvider?
    weak var context : TLSContext?
    var protocolVersion: TLSProtocolVersion
    var isClient : Bool
    
    private var currentReadEncryptionParameters  : EncryptionParameters?
    private var pendingReadEncryptionParameters  : EncryptionParameters?
    private var currentWriteEncryptionParameters : EncryptionParameters?
    private var pendingWriteEncryptionParameters : EncryptionParameters?

    var pendingSecurityParameters  : TLSSecurityParameters? {
        didSet {
            if let s = pendingSecurityParameters, hmacDescriptor = s.hmacDescriptor {
                
                let numberOfKeyMaterialBytes = 2 * (hmacDescriptor.size + s.encodeKeyLength + s.fixedIVLength)
                var keyBlock = self.context!.PRF(secret: s.masterSecret!, label: TLSKeyExpansionLabel, seed: s.serverRandom! + s.clientRandom!, outputLength: numberOfKeyMaterialBytes)
                
                var index = 0
                let clientWriteMACKey = [UInt8](keyBlock[index..<index + hmacDescriptor.size])
                index += hmacDescriptor.size
                
                let serverWriteMACKey = [UInt8](keyBlock[index..<index + hmacDescriptor.size])
                index += hmacDescriptor.size
                
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
                    readEncryptionParameters  = EncryptionParameters(hmacDescriptor: hmacDescriptor,
                        MACKey: serverWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: serverWriteKey,
                        blockLength: s.blockLength,
                        IV: serverWriteIV)
                    
                    writeEncryptionParameters = EncryptionParameters(hmacDescriptor: hmacDescriptor,
                        MACKey: clientWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: clientWriteKey,
                        blockLength: s.blockLength,
                        IV: clientWriteIV)
                }
                else {
                    readEncryptionParameters  = EncryptionParameters(hmacDescriptor: hmacDescriptor,
                        MACKey: clientWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: clientWriteKey,
                        blockLength: s.blockLength,
                        IV: clientWriteIV)
                    writeEncryptionParameters = EncryptionParameters(hmacDescriptor: hmacDescriptor,
                        MACKey: serverWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: serverWriteKey,
                        blockLength: s.blockLength,
                        IV: serverWriteIV)
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
        print(self.pendingWriteEncryptionParameters)
        self.currentWriteEncryptionParameters = self.pendingWriteEncryptionParameters
        self.pendingWriteEncryptionParameters = nil
    }

    init(context: TLSContext, dataProvider: TLSDataProvider)
    {
        self.context = context
        self.protocolVersion = context.configuration.protocolVersion
        self.dataProvider = dataProvider
        self.isClient = context.isClient
    }
    
    
    func sendData(contentType contentType: ContentType, data: [UInt8]) throws
    {
        if let encryptionParameters = self.currentWriteEncryptionParameters {
            let secret = encryptionParameters.MACKey
            
            if self.protocolVersion >= TLSProtocolVersion.TLS_v1_1 {
                encryptionParameters.IV = TLSRandomBytes(encryptionParameters.blockLength)
            }

            if let MAC = calculateMessageMAC(secret: secret, contentType: contentType, data: data, isRead: false) {
                
                var plainTextRecordData = data + MAC
                if self.protocolVersion >= TLSProtocolVersion.TLS_v1_1 {
                    plainTextRecordData = encryptionParameters.IV + plainTextRecordData
                }
                
                let blockLength = encryptionParameters.blockLength
                if blockLength > 0 {
                    let paddingLength = blockLength - ((plainTextRecordData.count) % blockLength)
                    if paddingLength != 0 {
                        let padding = [UInt8](count: paddingLength, repeatedValue: UInt8(paddingLength - 1))
                        
                        plainTextRecordData.appendContentsOf(padding)
                    }
                }
                
                var cipherText : [UInt8]
                if let b = encrypt(plainTextRecordData, key: encryptionParameters.bulkKey, IV: encryptionParameters.IV) {
                    cipherText = b
                }
                else {
                    throw TLSError.Error("Could not encrypt")
                }
                
                encryptionParameters.sequenceNumber += 1

                let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: cipherText)
                try self.dataProvider?.writeData(DataBuffer(record).buffer)
            }
        }
        else {
            // no security parameters have been negotiated yet
            let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: data)
            try self.dataProvider?.writeData(DataBuffer(record).buffer)
        }
    }
    
    func sendMessage(message : TLSMessage) throws
    {
        let contentType = message.contentType
        let messageData = DataBuffer(message).buffer
        
        try self.sendData(contentType: contentType, data: messageData)
    }

    
    
    func readMessage() throws -> TLSMessage
    {
        let headerProbeLength = TLSRecord.headerProbeLength
        
        let header = try self.dataProvider!.readData(count: headerProbeLength)
            
        guard
            let (contentType, bodyLength) = TLSRecord.probeHeader(header) else {
                throw TLSError.Error("Probe failed with malformed header \(header)")
        }
        
        let body = try self.dataProvider!.readData(count: bodyLength)

        var messageBody : [UInt8]
        if let encryptionParameters = self.currentReadEncryptionParameters {
            if let decryptedMessage = self.decryptAndVerifyMAC(contentType: contentType, data: body) {
                messageBody = decryptedMessage
            }
            else {
                fatalError("Could not decrypt")
            }
            encryptionParameters.sequenceNumber += 1
        }
        else {
            messageBody = body
        }
        
        let message : TLSMessage?
        switch (contentType)
        {
        case .ChangeCipherSpec:
            message = TLSChangeCipherSpec(inputStream: BinaryInputStream(messageBody), context: self.context!)
            
        case .Alert:
            message = TLSAlertMessage.alertFromData(messageBody, context: self.context!)
            
        case .Handshake:
            message = TLSHandshakeMessage.handshakeMessageFromData(messageBody, context: self.context!)
            
        case .ApplicationData:
            return TLSApplicationData(applicationData: messageBody)
        }
        
        if let message = message {
            
            var messageBuffer = DataBuffer()
            message.writeTo(&messageBuffer)

//            assert(messageBody == messageBuffer.buffer)
            
            return message
        }
        else {
            throw TLSError.Error("Could not create TLSMessage")
        }
    }

    private func calculateMessageMAC(secret secret: [UInt8], contentType : ContentType, data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        if let encryptionParameters = isRead ? self.currentReadEncryptionParameters : self.currentWriteEncryptionParameters {
            let macData = DataBuffer()
            macData.write(encryptionParameters.sequenceNumber)
            macData.write(contentType.rawValue)
            macData.write(self.protocolVersion.rawValue)
            macData.write(UInt16(data.count))
            macData.write(data)
                        
            return self.calculateMAC(secret: secret, data: macData.buffer, isRead: isRead)
        }
        
        return nil
    }
    
    private func calculateMAC(secret secret : [UInt8], data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        var HMAC : (secret : [UInt8], data : [UInt8]) -> [UInt8]
        if let algorithm = isRead ? self.currentReadEncryptionParameters?.hmacDescriptor.algorithm : self.currentWriteEncryptionParameters?.hmacDescriptor.algorithm {
            switch (algorithm)
            {
            case .HMAC_MD5:
                HMAC = HMAC_MD5
                
            case .HMAC_SHA1:
                HMAC = HMAC_SHA1

            case .HMAC_SHA256:
                HMAC = HMAC_SHA256

            case .HMAC_SHA384:
                HMAC = HMAC_SHA384

            case .HMAC_SHA512:
                HMAC = HMAC_SHA512

            }
        }
        else {
            return nil
        }
        
        return HMAC(secret: secret, data: data)
    }
    
    private func encrypt(data : [UInt8], key : [UInt8], IV : [UInt8]) -> [UInt8]?
    {
        let encryptionParameters = self.currentWriteEncryptionParameters!
        
        if self.encryptor == nil
        {
            self.encryptor = BlockCipher.encryptionBlockCipher(encryptionParameters.bulkCipherAlgorithm, mode: encryptionParameters.blockCipherMode, key: key, IV: IV)
        }
        
        if self.protocolVersion >= TLSProtocolVersion.TLS_v1_1 {
            return self.encryptor.update(data: data, key: key, IV: IV)
        }
        else {
            return self.encryptor.update(data: data, key: key, IV: nil)
        }
    }

    private func decrypt(data : [UInt8], key : [UInt8], IV : [UInt8]) -> [UInt8]?
    {
        let encryptionParameters = self.currentReadEncryptionParameters!
        
        if self.decryptor == nil
        {
            self.decryptor = BlockCipher.decryptionBlockCipher(encryptionParameters.bulkCipherAlgorithm, mode: encryptionParameters.blockCipherMode, key: key, IV: IV)
        }
        
        if self.protocolVersion >= TLSProtocolVersion.TLS_v1_1 {
            return self.decryptor.update(data: data, key: key, IV: IV)
        }
        else {
            return self.decryptor.update(data: data, key: key, IV: nil)
        }
    }

    private func decryptAndVerifyMAC(contentType contentType : ContentType, data : [UInt8]) -> [UInt8]?
    {
        if let encryptionParameters = self.currentReadEncryptionParameters
        {
            if self.protocolVersion >= TLSProtocolVersion.TLS_v1_1 {
                encryptionParameters.IV = [UInt8](data[0..<encryptionParameters.blockLength])
            }
            
            if let decryptedMessage = decrypt(data, key: encryptionParameters.bulkKey, IV: encryptionParameters.IV) {
                var message : [UInt8]
                if self.protocolVersion >= TLSProtocolVersion.TLS_v1_1 {
                    message = [UInt8](decryptedMessage[encryptionParameters.blockLength..<decryptedMessage.count])
                }
                else {
                    message = decryptedMessage
                }
                
                let hmacLength = encryptionParameters.hmacDescriptor.size
                var messageLength = message.count - hmacLength
                
                if encryptionParameters.blockLength > 0 {
                    let padding = message.last!
                    let paddingLength = Int(padding) + 1
                    var paddingIsCorrect = (paddingLength < message.count)
                    paddingIsCorrect = paddingIsCorrect && (message[(message.count - paddingLength) ..< message.count].filter({$0 != padding}).count == 0)
                    if !paddingIsCorrect {
                        print("Error: could not decrypt message")
                        return nil
                    }
                    messageLength -= paddingLength
                }
                
                let messageContent = [UInt8](message[0..<messageLength])
                
                let MAC = [UInt8](message[messageLength..<messageLength + hmacLength])
                
                let messageMAC = self.calculateMessageMAC(secret: encryptionParameters.MACKey, contentType: contentType, data: messageContent, isRead: true)
                
                if let messageMAC = messageMAC where MAC == messageMAC {
                    return messageContent
                }
                else {
                    print("Error: MAC doesn't match")
                }
            }
        }
        
        return nil
    }
}