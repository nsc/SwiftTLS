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
    var macAlgorithm : MACAlgorithm
    var bulkCipherAlgorithm : CipherAlgorithm
    var MACKey  : [UInt8]
    var bulkKey : [UInt8]
    var blockLength : Int
    var IV      : [UInt8]
    var sequenceNumber : UInt64
    
    init(macAlgorithm : MACAlgorithm, MACKey: [UInt8], bulkCipherAlgorithm: CipherAlgorithm, bulkKey: [UInt8], blockLength: Int, IV: [UInt8], sequenceNumber: UInt64 = UInt64(0))
    {
        self.macAlgorithm = macAlgorithm
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
    var protocolVersion: TLSProtocolVersion
    var isClient : Bool
    
    private var currentReadEncryptionParameters : EncryptionParameters?
    private var pendingReadEncryptionParameters : EncryptionParameters?
    private var currentWriteEncryptionParameters : EncryptionParameters?
    private var pendingWriteEncryptionParameters : EncryptionParameters?

    var pendingSecurityParameters  : TLSSecurityParameters? {
        didSet {
            if let s = pendingSecurityParameters {
                
                var numberOfKeyMaterialBytes = 2 * (s.macKeyLength + s.encodeKeyLength + s.fixedIVLength)
                var keyBlock = PRF(secret: s.masterSecret!, label: TLSKeyExpansionLabel, seed: s.serverRandom! + s.clientRandom!, outputLength: numberOfKeyMaterialBytes)
                
                var index = 0
                var clientWriteMACKey = [UInt8](keyBlock[index..<index + s.macKeyLength])
                index += s.macKeyLength
                
                var serverWriteMACKey = [UInt8](keyBlock[index..<index + s.macKeyLength])
                index += s.macKeyLength
                
                var clientWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
                index += s.encodeKeyLength
                
                var serverWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
                index += s.encodeKeyLength
                
                var clientWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
                index += s.fixedIVLength
                
                var serverWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
                index += s.fixedIVLength
                
                var readEncryptionParameters  : EncryptionParameters
                var writeEncryptionParameters : EncryptionParameters
                
                if self.isClient {
                    readEncryptionParameters  = EncryptionParameters(macAlgorithm: s.macAlgorithm!,
                        MACKey: serverWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: serverWriteKey,
                        blockLength: s.blockLength,
                        IV: serverWriteIV)
                    
                    writeEncryptionParameters = EncryptionParameters(macAlgorithm: s.macAlgorithm!,
                        MACKey: clientWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: clientWriteKey,
                        blockLength: s.blockLength,
                        IV: clientWriteIV)
                }
                else {
                    readEncryptionParameters  = EncryptionParameters(macAlgorithm: s.macAlgorithm!,
                        MACKey: clientWriteMACKey,
                        bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                        bulkKey: clientWriteKey,
                        blockLength: s.blockLength,
                        IV: clientWriteIV)
                    writeEncryptionParameters = EncryptionParameters(macAlgorithm: s.macAlgorithm!,
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

    init(protocolVersion: TLSProtocolVersion, dataProvider: TLSDataProvider, isClient : Bool)
    {
        self.protocolVersion = protocolVersion
        self.dataProvider = dataProvider
        self.isClient = isClient
    }
    
    
    func sendData(#contentType: ContentType, data: [UInt8], completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        
        if contentType == ContentType.Handshake {
            if let handshake = TLSHandshakeMessage.handshakeMessageFromData(data) {
                println("\(handshake)")
            }
        }
        
        if let encryptionParameters = self.currentWriteEncryptionParameters {
            var secret = encryptionParameters.MACKey
            
            if let MAC = calculateMessageMAC(secret: secret, contentType: contentType, data: data, isRead: false) {
                
                var plainTextRecordData = data + MAC
                var blockLength = encryptionParameters.blockLength
                if blockLength > 0 {
                    var paddingLength = blockLength - ((plainTextRecordData.count) % blockLength)
                    if paddingLength != 0 {
                        var padding = [UInt8](count: paddingLength, repeatedValue: UInt8(paddingLength - 1))
                        
                        plainTextRecordData.extend(padding)
                    }
                }
                
                var cipherText : [UInt8]
                println("plain text record data: \(hex(plainTextRecordData))")
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
                var record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: cipherText)
                self.dataProvider?.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
            }
        }
        else {
            // no security parameters have been negotiated yet
            var record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: data)
            self.dataProvider?.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
        }
    }
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        let contentType = message.contentType
        var messageData = DataBuffer(message).buffer
        
        self.sendData(contentType: contentType, data: messageData, completionBlock: completionBlock)
    }

    
    
    func readMessage(#completionBlock: (message : TLSMessage?) -> ())
    {
        let headerProbeLength = TLSRecord.headerProbeLength
        
        self.dataProvider?.readData(count: headerProbeLength) { (data, error) -> () in
            
            if let header = data {
                if let (contentType, bodyLength) = TLSRecord.probeHeader(header) {
                    
                    var body : [UInt8] = []
                    
                    var recursiveBlock : ((data : [UInt8]?, error : TLSDataProviderError?) -> ())!
                    var readBlock : (data : [UInt8]?, error : TLSDataProviderError?) -> () = { (data, error) -> () in
                        
                        if let d = data {
                            body.extend(d)
                            
                            if body.count < bodyLength {
                                var rest = bodyLength - body.count
                                self.dataProvider?.readData(count:rest , completionBlock: recursiveBlock)
                                return
                            }
                            else {
                                var messageBody : [UInt8]
                                if let encryptionParameters = self.currentReadEncryptionParameters {
                                    if let decryptedMessage = self.decryptAndVerifyMAC(body) {
                                        messageBody = decryptedMessage
                                    }
                                    else {
                                        fatalError("Could not decrypt")
                                    }
                                }
                                else {
                                    messageBody = body
                                }

                                if let record = TLSRecord(inputStream: BinaryInputStream(data: header + messageBody)) {
                                    switch (record.contentType)
                                    {
                                    case .ChangeCipherSpec:
                                        var changeCipherSpec = TLSChangeCipherSpec(inputStream: BinaryInputStream(data: messageBody))
                                        completionBlock(message: changeCipherSpec)
                                        break
                                        
                                    case .Alert:
                                        var alert = TLSAlert.alertFromData(messageBody)
                                        completionBlock(message: alert)
                                        break
                                        
                                    case .Handshake:
                                        var handshakeMessage = TLSHandshakeMessage.handshakeMessageFromData(messageBody)
                                        completionBlock(message: handshakeMessage)
                                        break
                                        
                                    case .ApplicationData:
                                        break
                                    }
                                }
                            }
                        }
                        
                    }
                    recursiveBlock = readBlock
                    
                    self.dataProvider?.readData(count: bodyLength, completionBlock: readBlock)
                }
                else {
                    fatalError("Probe failed")
                }
            }
        }
    }

    private func calculateMessageMAC(#secret: [UInt8], contentType : ContentType, data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        if let encryptionParameters = self.currentWriteEncryptionParameters {
            var macData = DataBuffer()
            write(macData, encryptionParameters.sequenceNumber)
            write(macData, contentType.rawValue)
            write(macData, self.protocolVersion.rawValue)
            write(macData, UInt16(data.count))
            write(macData, data)
            
            println("mac data: \(hex(macData.buffer))")
            
            return self.calculateMAC(secret: secret, data: macData.buffer, isRead: isRead)
        }
        
        return nil
    }
    
    private func calculateMAC(#secret : [UInt8], var data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        var HMAC : (secret : [UInt8], data : [UInt8]) -> [UInt8]
        if let algorithm = isRead ? self.currentReadEncryptionParameters?.macAlgorithm : self.currentWriteEncryptionParameters?.macAlgorithm {
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
        
        return nil
    }

    private func encrypt(var data : [UInt8]) -> [UInt8]?
    {
        if self.currentWriteEncryptionParameters == nil {
            return nil
        }
    
        var encryptionParameters = self.currentWriteEncryptionParameters!
        
        var algorithm = self.CCCipherAlgorithmForCipherAlgorithm(encryptionParameters.bulkCipherAlgorithm)
        if self.encryptor == nil
        {
            if algorithm == nil {
                return data
            }
            
            var key = encryptionParameters.bulkKey
            var IV  = encryptionParameters.IV
            var encryptor = CCCryptorRef()

            var status = Int(CCCryptorCreate(CCOperation(kCCEncrypt), algorithm!, 0, &key, key.count, &IV, &encryptor))
            if status != kCCSuccess {
                println("Error: Could not create encryptor")
                return nil
            }
            
            self.encryptor = encryptor
        }
        
        var outputLength : Int = CCCryptorGetOutputLength(self.encryptor!, data.count, false)
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
        var status = outputData.withUnsafeMutableBufferPointer { (inout outputBuffer : UnsafeMutableBufferPointer<UInt8>) -> Int in
            var outputDataWritten : Int = 0
            var status = Int(CCCryptorUpdate(self.encryptor!, data, data.count, outputBuffer.baseAddress, outputLength, &outputDataWritten))
            assert(outputDataWritten == outputLength)
            return status
        }
        
        if status != kCCSuccess {
            println("Error: Could not encrypt data")
            return nil
        }
        
        return outputData
    }

    private func decrypt(var data : [UInt8]) -> [UInt8]?
    {
        if self.currentReadEncryptionParameters == nil {
            return nil
        }
        
        var encryptionParameters = self.currentReadEncryptionParameters!
        
        var algorithm = self.CCCipherAlgorithmForCipherAlgorithm(encryptionParameters.bulkCipherAlgorithm)
        if self.decryptor == nil
        {
            if algorithm == nil {
                return data
            }
            
            var key = encryptionParameters.bulkKey
            var IV  = encryptionParameters.IV
            var decryptor = CCCryptorRef()
            
            var status = Int(CCCryptorCreate(CCOperation(kCCDecrypt), algorithm!, 0, &key, key.count, &IV, &decryptor))
            if status != kCCSuccess {
                println("Error: Could not create encryptor")
                return nil
            }
            
            self.decryptor = decryptor
        }
        
        var outputLength : Int = CCCryptorGetOutputLength(self.decryptor!, data.count, false)
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
        var status = outputData.withUnsafeMutableBufferPointer { (inout outputBuffer : UnsafeMutableBufferPointer<UInt8>) -> Int in
            var outputDataWritten : Int = 0
            var status = Int(CCCryptorUpdate(self.decryptor!, data, data.count, outputBuffer.baseAddress, outputLength, &outputDataWritten))
            assert(outputDataWritten == outputLength)
            return status
        }
        
        if status != kCCSuccess {
            println("Error: Could not encrypt data")
            return nil
        }
        
        return outputData
    }

    private func decryptAndVerifyMAC(var data : [UInt8]) -> [UInt8]?
    {
        if let decryptedMessage = decrypt(data) {
            return decryptedMessage
        }
        
        return nil
    }
}