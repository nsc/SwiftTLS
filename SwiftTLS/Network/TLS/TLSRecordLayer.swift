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
    private var securityParameters : TLSSecurityParameters!
    private var encryptor : CCCryptorRef!
    private var decryptor : CCCryptorRef!
    
    func activateSecurityParameters(securityParameters : TLSSecurityParameters)
    {
        self.securityParameters = securityParameters
        
        let s = securityParameters
        
        var numberOfKeyMaterialBytes = 2 * (s.macKeyLength + s.encodeKeyLength + s.fixedIVLength)
        var keyBlock = PRF(secret: s.masterSecret!, label: TLSKeyExpansionLabel, seed: s.serverRandom! + s.clientRandom!, outputLength: numberOfKeyMaterialBytes)
        
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
    
    init(protocolVersion: TLSProtocolVersion, dataProvider: TLSDataProvider)
    {
        self.dataProvider = dataProvider
    }
    
    
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        let contentType : ContentType
        switch (message.type)
        {
        case .ChangeCipherSpec:
            contentType = .ChangeCipherSpec
            
        case .Alert:
            contentType = .Alert
            
        case .Handshake:
            contentType = .Handshake
            
        case .ApplicationData:
            contentType = .ApplicationData
        }
        
        var body = DataBuffer(message).buffer
        
        if self.securityParameters != nil {
            if let b = encryptAndMAC(body) {
                body = b
            }
            else {
                if let block = completionBlock {
                    block(nil)
                }
                return
            }
        }
        
        var record = TLSRecord(contentType: contentType, body: body)
        self.dataProvider.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
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

    private func encryptAndMAC(var data : [UInt8]) -> [UInt8]?
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
                return nil
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