//
//  TLSRecordLayer.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 03.02.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

protocol TLSRecordLayer
{
    var dataProvider : TLSDataProvider? { get set }
    var connection : TLSConnection?  { get set }
    var protocolVersion: TLSProtocolVersion  { get set }
    var isClient : Bool { get }

    func sendMessage(_ message : TLSMessage) throws
    func sendData(contentType: ContentType, data: [UInt8]) throws
    func readMessage() throws -> TLSMessage

    func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8]
    func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8])
}

class TLSBaseRecordLayer : TLSRecordLayer
{
    weak var dataProvider : TLSDataProvider?
    weak var connection : TLSConnection?
    var protocolVersion: TLSProtocolVersion
    var isClient : Bool
    
    var bufferedMessages: [TLSMessage]?

    init(connection: TLSConnection, dataProvider: TLSDataProvider? = nil)
    {
        self.connection = connection
        self.protocolVersion = TLSProtocolVersion.v1_0
        self.dataProvider = dataProvider
        self.isClient = connection.isClient
    }
    
    func sendMessage(_ message : TLSMessage) throws
    {
        let contentType = message.contentType
        let messageData = [UInt8](message, context: self.connection)
        
        try sendData(contentType: contentType, data: messageData)
    }

    func sendData(contentType: ContentType, data: [UInt8]) throws
    {
        let recordData = try self.recordData(forContentType: contentType, data: data)
        try self.dataProvider?.writeData(recordData)
    }
    
    func readRecordBody(count: Int) throws -> [UInt8]
    {
        return try self.dataProvider!.readData(count: count)
    }
    
    func readMessage() throws -> TLSMessage
    {
        if let bufferedMessages = self.bufferedMessages {
            if bufferedMessages.count > 0 {
                let resultMessage = bufferedMessages[0]
                self.bufferedMessages = [TLSMessage](bufferedMessages[1 ..< bufferedMessages.count])
                
                return resultMessage
            }
        }
        let headerProbeLength = TLSRecord.headerProbeLength
        
        let header = try self.dataProvider!.readData(count: headerProbeLength)
        
        guard let (contentType, bodyLength) = TLSRecord.probeHeader(header) else {
            throw TLSError.error("Probe failed with malformed header \(header)")
        }
        
        let body = try self.readRecordBody(count: bodyLength)
        
        var (contentTypeFromRecord, messageBody) = try self.data(forContentType: contentType, recordData: body)
        
        var messages: [TLSMessage] = []
        
        while messageBody.count > 0 {
            let message : TLSMessage?
            switch (contentTypeFromRecord)
            {
            case .changeCipherSpec:
                message = TLSChangeCipherSpec(inputStream: BinaryInputStream(messageBody), context: self.connection!)
                messageBody = []
                
            case .alert:
                message = TLSAlertMessage.alertFromData(messageBody, context: self.connection!)
                messageBody = []
                
            case .handshake:
                let result = TLSHandshakeMessage.handshakeMessageFromData(messageBody, context: self.connection!)
                message = result.0
                messageBody = result.1 ?? []
                
            case .applicationData:
                message = TLSApplicationData(applicationData: messageBody)
                messageBody = []
            }
            
            if let message = message {
                messages.append(message)
            }
            else {
                throw TLSError.error("Could not create TLSMessage")
            }
        }
        
        let resultMessage = messages[0]
        self.bufferedMessages = [TLSMessage](messages[1 ..< messages.count])
        return resultMessage
    }

    func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8] {
        fatalError("sendData not implemented")
    }

    func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8]) {
        fatalError("decryptMessageBody not implemented")
    }
}
