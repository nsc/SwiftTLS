//
//  TLSRecordLayer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

class TLSRecordLayer
{
    weak var dataProvider : TLSDataProvider!
    var protocolVersion: TLSProtocolVersion
    
    private var securityParameters : TLSSecurityParameters!
    private var encryptor : CCCryptorRef!
    private var decryptor : CCCryptorRef!
    
    func activateSecurityParameters(securityParameters : TLSSecurityParameters)
    {
        self.securityParameters = securityParameters
        
        let s = securityParameters
        
        var numberOfKeyMaterialBytes = 2 * (s.macKeyLength + s.encodeKeyLength + s.fixedIVLength)
        var keyBlock = PRF(secret: s.masterSecret!, label: TLSKeyExpansionLabel, seed: s.serverRandom! + s.clientRandom!, outputLength: numberOfKeyMaterialBytes)
        
        println("key block: \(hex(keyBlock))")
        
        var index = 0
        self.clientWriteMACKey = [UInt8](keyBlock[index..<index + s.macKeyLength])
        index += s.macKeyLength
        
        self.serverWriteMACKey = [UInt8](keyBlock[index..<index + s.macKeyLength])
        index += s.macKeyLength
        
        self.clientWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
        index += s.encodeKeyLength
        
        self.serverWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
        index += s.encodeKeyLength
        
        self.clientWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
        index += s.fixedIVLength
        
        self.serverWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
        index += s.fixedIVLength
    }

    var clientWriteMACKey : [UInt8]?
    var serverWriteMACKey : [UInt8]?
    var clientWriteKey : [UInt8]?
    var serverWriteKey : [UInt8]?
    var clientWriteIV : [UInt8]?
    var serverWriteIV : [UInt8]?
    var clientWriteSequenceNumber : UInt64 = 0
    var serverWriteSequenceNumber : UInt64 = 0
    
    init(protocolVersion: TLSProtocolVersion, dataProvider: TLSDataProvider)
    {
        self.protocolVersion = protocolVersion
        self.dataProvider = dataProvider
    }
    
    
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        let contentType = message.contentType
        var messageData = DataBuffer(message).buffer
        
        if contentType == ContentType.Handshake {
            if let handshake = TLSHandshakeMessage.handshakeMessageFromData(messageData) {
                println("\(handshake)")
            }
        }
        
        if self.securityParameters != nil {
            var secret = self.securityParameters.connectionEnd == .Client ? self.clientWriteMACKey! : self.serverWriteMACKey!

            if let MAC = calculateMessageMAC(secret: secret, contentType: message.contentType, messageData: messageData) {
            
                var plainTextRecordData = messageData + MAC
                var blockLength = self.securityParameters.blockLength
                if blockLength > 0 {
                    var paddingLength = blockLength - ((plainTextRecordData.count + TLS_RecordHeaderLength) % blockLength)
                    if paddingLength != 0 {
                        var padding = [UInt8](count: paddingLength, repeatedValue: UInt8(paddingLength - 1))
                        
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
                
                self.clientWriteSequenceNumber += 1
                var record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: cipherText)
                self.dataProvider.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
            }
        }
        else {
            // no security parameters have been negotiated yet
            var record = TLSRecord(contentType: contentType, protocolVersion: self.protocolVersion, body: messageData)
            self.dataProvider.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
        }
    }

    
    
    func readMessage(#completionBlock: (message : TLSMessage?) -> ())
    {
        let headerProbeLength = TLSRecord.headerProbeLength
        
        self.dataProvider.readData(count: headerProbeLength) { (data, error) -> () in
            
            if let header = data {
                if let (contentType, bodyLength) = TLSRecord.probeHeader(header) {
                    
                    var body : [UInt8] = []
                    
                    var recursiveBlock : ((data : [UInt8]?, error : TLSDataProviderError?) -> ())!
                    var readBlock : (data : [UInt8]?, error : TLSDataProviderError?) -> () = { (data, error) -> () in
                        
                        if let d = data {
                            body.extend(d)
                            
                            if body.count < bodyLength {
                                var rest = bodyLength - body.count
                                self.dataProvider.readData(count:rest , completionBlock: recursiveBlock)
                                return
                            }
                            else {
                                if let record = TLSRecord(inputStream: BinaryInputStream(data: header + body)) {
                                    switch (record.contentType)
                                    {
                                    case .ChangeCipherSpec:
                                        var changeCipherSpec = TLSChangeCipherSpec(inputStream: BinaryInputStream(data: body))
                                        completionBlock(message: changeCipherSpec)
                                        break
                                        
                                    case .Alert:
                                        var alert = TLSAlert.alertFromData(body)
                                        completionBlock(message: alert)
                                        break
                                        
                                    case .Handshake:
                                        var handshakeMessage = TLSHandshakeMessage.handshakeMessageFromData(body)
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
                    
                    self.dataProvider.readData(count: bodyLength, completionBlock: readBlock)
                }
                else {
                    fatalError("Probe failed")
                }
            }
        }
    }

    private func calculateMessageMAC(#secret: [UInt8], contentType : ContentType, messageData : [UInt8]) -> [UInt8]?
    {
        var macData = DataBuffer()
        write(macData, self.clientWriteSequenceNumber)
        write(macData, contentType.rawValue)
        write(macData, self.protocolVersion.rawValue)
        write(macData, UInt16(messageData.count))
        write(macData, messageData)
        
        println("mac data: \(hex(macData.buffer))")
        
        return self.calculateMAC(secret: secret, data: macData.buffer)
    }
    
    private func calculateMAC(#secret : [UInt8], var data : [UInt8]) -> [UInt8]?
    {
        var HMAC : (secret : [UInt8], data : [UInt8]) -> [UInt8]
        if let algorithm = self.securityParameters.macAlgorithm {
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
    
    private func encrypt(var data : [UInt8]) -> [UInt8]?
    {
        if self.securityParameters == nil {
            return nil
        }
    
        var algorithm : CCAlgorithm?
        switch (self.securityParameters.bulkCipherAlgorithm!)
        {
        case .AES:
            algorithm = CCAlgorithm(kCCAlgorithmAES)
            
        case .TRIPLE_DES:
            algorithm = CCAlgorithm(kCCAlgorithm3DES)
            
        case .NULL:
            algorithm = nil
        }

        if let encryptor = self.encryptor {
        }
        else {
            if algorithm == nil {
                return data
            }
            
            var encryptor = CCCryptorRef()
            var status = Int(CCCryptorCreate(CCOperation(kCCEncrypt), algorithm!, 0, &self.clientWriteKey!, self.clientWriteKey!.count, &self.clientWriteIV!, &encryptor))
            if status != kCCSuccess {
                println("Error: Could not create encryptor")
                return nil
            }
            
            self.encryptor = encryptor
        }
        
        var outputLength : Int = CCCryptorGetOutputLength(self.encryptor, data.count, false)
        var outputData = [UInt8](count: outputLength, repeatedValue: 0)
        
        var status = outputData.withUnsafeMutableBufferPointer { (inout outputBuffer : UnsafeMutableBufferPointer<UInt8>) -> Int in
            var outputDataWritten : Int = 0
            var status = Int(CCCryptorUpdate(self.encryptor, data, data.count, outputBuffer.baseAddress, outputLength, &outputDataWritten))
            assert(outputDataWritten == outputLength)
            return status
        }
        
        if status != kCCSuccess {
            println("Error: Could not encrypt data")
            return nil
        }
        
        return outputData
    }
}