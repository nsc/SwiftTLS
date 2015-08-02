//
//  TLSRecordLayer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

class EncryptionParameters {
    var hmacDescriptor : HMACDescriptor
    var bulkCipherAlgorithm : CipherAlgorithm
    var MACKey  : [UInt8]
    var bulkKey : [UInt8]
    var blockLength : Int
    var IV      : [UInt8]
    var sequenceNumber : UInt64
    
    init(hmacDescriptor : HMACDescriptor, MACKey: [UInt8], bulkCipherAlgorithm: CipherAlgorithm, bulkKey: [UInt8], blockLength: Int, IV: [UInt8], sequenceNumber: UInt64 = UInt64(0))
    {
        self.hmacDescriptor = hmacDescriptor
        self.bulkCipherAlgorithm = bulkCipherAlgorithm
        self.MACKey = MACKey
        self.bulkKey = bulkKey
        self.blockLength = blockLength
        self.IV = IV
        self.sequenceNumber = sequenceNumber
    }
    
}

class TLSRecordLayer
{
    weak var dataProvider : TLSDataProvider?
    weak var context : TLSContext?
    var protocolVersion: TLSProtocolVersion
    var isClient : Bool
    
    private var currentReadEncryptionParameters : EncryptionParameters?
    private var pendingReadEncryptionParameters : EncryptionParameters?
    private var currentWriteEncryptionParameters : EncryptionParameters?
    private var pendingWriteEncryptionParameters : EncryptionParameters?

    var pendingSecurityParameters  : TLSSecurityParameters? {
        didSet {
            if let s = pendingSecurityParameters, hmacDescriptor = s.hmacDescriptor {
                
                let numberOfKeyMaterialBytes = 2 * (hmacDescriptor.size + s.encodeKeyLength + s.fixedIVLength)
                var keyBlock = PRF(secret: s.masterSecret!, label: TLSKeyExpansionLabel, seed: s.serverRandom! + s.clientRandom!, outputLength: numberOfKeyMaterialBytes)
                
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

    private var encryptor : CCCryptorRef?
    private var decryptor : CCCryptorRef?

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

    init(context: TLSContext, dataProvider: TLSDataProvider)
    {
        self.context = context
        self.protocolVersion = context.protocolVersion
        self.dataProvider = dataProvider
        self.isClient = context.isClient
    }
    
    
    func sendData(contentType contentType: ContentType, data: [UInt8], completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        
        if let encryptionParameters = self.currentWriteEncryptionParameters {
            let secret = encryptionParameters.MACKey
            
            if let MAC = calculateMessageMAC(secret: secret, contentType: contentType, data: data, isRead: false) {
                
                var plainTextRecordData = data + MAC
                let blockLength = encryptionParameters.blockLength
                if blockLength > 0 {
                    let paddingLength = blockLength - ((plainTextRecordData.count) % blockLength)
                    if paddingLength != 0 {
                        let padding = [UInt8](count: paddingLength, repeatedValue: UInt8(paddingLength - 1))
                        
                        plainTextRecordData.extend(padding)
                    }
                }
                
                var cipherText : [UInt8]
                if let b = encrypt(plainTextRecordData) {
                    cipherText = b
                }
                else {
                    if let block = completionBlock {
                        block(nil)
                    }
                    return
                }
                
                encryptionParameters.sequenceNumber += 1
                let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: cipherText)
                self.dataProvider?.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
            }
        }
        else {
            // no security parameters have been negotiated yet
            let record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: data)
            self.dataProvider?.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
        }
    }
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        let contentType = message.contentType
        let messageData = DataBuffer(message).buffer
        
        self.sendData(contentType: contentType, data: messageData, completionBlock: completionBlock)
    }

    
    
    func readMessage(completionBlock completionBlock: (message : TLSMessage?) -> ())
    {
        let headerProbeLength = TLSRecord.headerProbeLength
        
        self.dataProvider?.readData(count: headerProbeLength) { (data, error) -> () in
            
            guard
                let header = data,
                let (contentType, bodyLength) = TLSRecord.probeHeader(header) else {

                    fatalError("Probe failed")
            }
                    
            var body : [UInt8] = []
            
            var recursiveBlock : ((data : [UInt8]?, error : TLSDataProviderError?) -> ())!
            let readBlock : (data : [UInt8]?, error : TLSDataProviderError?) -> () = { (data, error) -> () in
                
                if let d = data {
                    body.extend(d)
                    
                    if body.count < bodyLength {
                        let rest = bodyLength - body.count
                        self.dataProvider?.readData(count:rest , completionBlock: recursiveBlock)
                        return
                    }
                    else {
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
                        
                        switch (contentType)
                        {
                        case .ChangeCipherSpec:
                            let changeCipherSpec = TLSChangeCipherSpec(inputStream: BinaryInputStream(data: messageBody))
                            completionBlock(message: changeCipherSpec)
                            break
                            
                        case .Alert:
                            let alert = TLSAlertMessage.alertFromData(messageBody)
                            completionBlock(message: alert)
                            break
                            
                        case .Handshake:
                            let handshakeMessage = TLSHandshakeMessage.handshakeMessageFromData(messageBody, context: self.context)
                            completionBlock(message: handshakeMessage)
                            break
                            
                        case .ApplicationData:
                            completionBlock(message: TLSApplicationData(applicationData: messageBody))
                            break
                        }
                    }
                }
                
            }
            recursiveBlock = readBlock
            
            self.dataProvider?.readData(count: bodyLength, completionBlock: readBlock)
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
    
    private func CCCipherAlgorithmForCipherAlgorithm(cipherAlgorithm : CipherAlgorithm) -> CCAlgorithm?
    {
        switch (cipherAlgorithm)
        {
        case .AES:
            return CCAlgorithm(kCCAlgorithmAES)
            
        case .TRIPLE_DES:
            return CCAlgorithm(kCCAlgorithm3DES)
            
        case .NULL:
            return nil
        }
    }

    private func encrypt(data : [UInt8]) -> [UInt8]?
    {
        if self.currentWriteEncryptionParameters == nil {
            return nil
        }
    
        let encryptionParameters = self.currentWriteEncryptionParameters!
        
        let algorithm = self.CCCipherAlgorithmForCipherAlgorithm(encryptionParameters.bulkCipherAlgorithm)
        if self.encryptor == nil
        {
            if algorithm == nil {
                return data
            }
            
            var key = encryptionParameters.bulkKey
            var IV  = encryptionParameters.IV
            var encryptor = CCCryptorRef()

            let status = Int(CCCryptorCreate(CCOperation(kCCEncrypt), algorithm!, 0, &key, key.count, &IV, &encryptor))
            if status != kCCSuccess {
                print("Error: Could not create encryptor")
                return nil
            }
            
            self.encryptor = encryptor
        }
        
        let outputLength : Int = CCCryptorGetOutputLength(self.encryptor!, data.count, false)
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
        let status = outputData.withUnsafeMutableBufferPointer { (inout outputBuffer : UnsafeMutableBufferPointer<UInt8>) -> Int in
            var outputDataWritten : Int = 0
            let status = Int(CCCryptorUpdate(self.encryptor!, data, data.count, outputBuffer.baseAddress, outputLength, &outputDataWritten))
            assert(outputDataWritten == outputLength)
            return status
        }
        
        if status != kCCSuccess {
            print("Error: Could not encrypt data")
            return nil
        }
        
        return outputData
    }

    private func decrypt(data : [UInt8]) -> [UInt8]?
    {
        if self.currentReadEncryptionParameters == nil {
            return nil
        }
        
        let encryptionParameters = self.currentReadEncryptionParameters!
        
        let algorithm = self.CCCipherAlgorithmForCipherAlgorithm(encryptionParameters.bulkCipherAlgorithm)
        if self.decryptor == nil
        {
            if algorithm == nil {
                return data
            }
            
            var key = encryptionParameters.bulkKey
            var IV  = encryptionParameters.IV
            var decryptor = CCCryptorRef()
            
            let status = Int(CCCryptorCreate(CCOperation(kCCDecrypt), algorithm!, 0, &key, key.count, &IV, &decryptor))
            if status != kCCSuccess {
                print("Error: Could not create encryptor")
                return nil
            }
            
            self.decryptor = decryptor
        }
        
        let outputLength : Int = CCCryptorGetOutputLength(self.decryptor!, data.count, false)
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
        let status = outputData.withUnsafeMutableBufferPointer { (inout outputBuffer : UnsafeMutableBufferPointer<UInt8>) -> Int in
            var outputDataWritten : Int = 0
            let status = Int(CCCryptorUpdate(self.decryptor!, data, data.count, outputBuffer.baseAddress, outputLength, &outputDataWritten))
            assert(outputDataWritten == outputLength)
            return status
        }
        
        if status != kCCSuccess {
            print("Error: Could not encrypt data")
            return nil
        }
        
        return outputData
    }

    private func decryptAndVerifyMAC(contentType contentType : ContentType, data : [UInt8]) -> [UInt8]?
    {
        if let decryptedMessage = decrypt(data) {
            
            if let encryptionParameters = self.currentReadEncryptionParameters
            {
                let hmacLength = encryptionParameters.hmacDescriptor.size
                var messageLength = decryptedMessage.count - hmacLength
                
                if encryptionParameters.blockLength > 0 {
                    let paddingLength = Int(decryptedMessage.last!) + 1
                    messageLength -= paddingLength
                }
                
                let messageContent = [UInt8](decryptedMessage[0..<messageLength])
                
                let MAC = [UInt8](decryptedMessage[messageLength..<messageLength + hmacLength])
                
                let messageMAC = self.calculateMessageMAC(secret: encryptionParameters.MACKey, contentType: contentType, data: messageContent, isRead: true)
                
                if let messageMAC = messageMAC where MAC == messageMAC {
                    return messageContent
                }
            }
        }
        
        return nil
    }
}