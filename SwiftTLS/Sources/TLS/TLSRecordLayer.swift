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
    func readMessage() throws -> TLSMessage?

    func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8]
    func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8])
}

class TLSBaseRecordLayer : TLSRecordLayer
{
    weak var dataProvider : TLSDataProvider?
    weak var connection : TLSConnection?
    var protocolVersion: TLSProtocolVersion
    var isClient : Bool
    
    var bufferedRawData: [UInt8] = []
    
    var bufferedContentType: ContentType?
    var bufferedRecordData: [UInt8] = []

    var maximumRecordSize: Int?
    
    init(connection: TLSConnection, dataProvider: TLSDataProvider? = nil)
    {
        self.connection = connection
        self.protocolVersion = TLSProtocolVersion.v1_0
        self.dataProvider = dataProvider
        self.isClient = connection.isClient
        self.maximumRecordSize = connection.configuration.maximumRecordSize
    }
    
    func sendMessage(_ message : TLSMessage) throws
    {
        let contentType = message.contentType
        let messageData = [UInt8](message, context: self.connection)
        
        try sendData(contentType: contentType, data: messageData)
    }

    func sendData(contentType: ContentType, data: [UInt8]) throws
    {
        if let maximumRecordSize = self.maximumRecordSize, maximumRecordSize < data.count {
            var start = 0
            var end = 0
            while end < data.count {
                
                start = end
                end += maximumRecordSize
                if end > data.count {
                    end = data.count
                }
                
                let recordData = try self.recordData(forContentType: contentType, data: [UInt8](data[start..<end]))
                try self.dataProvider?.writeData(recordData)
            }
        }
        else {
            let recordData = try self.recordData(forContentType: contentType, data: data)
            try self.dataProvider?.writeData(recordData)
        }
    }
    
    func readRecordBody(count: Int) throws -> [UInt8]
    {
        return try self.readData(count: count)
    }

    func readData(count: Int) throws -> [UInt8] {
        if self.bufferedRawData.count >= count {
            let data = [UInt8](self.bufferedRawData[0..<count])
            self.bufferedRawData = [UInt8](self.bufferedRawData.dropFirst(count))
            
            return data
        }
        
        let data = try self.dataProvider!.readData(count: count - self.bufferedRawData.count)
        self.bufferedRawData += data
        
        return try readData(count: count)
    }
    
    private func readRecordData() throws -> (ContentType, [UInt8])? {
        let headerProbeLength = TLSRecord.headerProbeLength
        let header = try self.readData(count: headerProbeLength)
        
        guard let (contentType, bodyLength) = TLSRecord.probeHeader(header) else {
            throw TLSError.error("Probe failed with malformed header \(header)")
        }
        
        let body = try self.readRecordBody(count: bodyLength)
        
        return try self.data(forContentType: contentType, recordData: body)
    }
    
    func readMessage() throws -> TLSMessage?
    {
        var messageBody: [UInt8]
        var contentTypeFromRecord: ContentType
        if self.bufferedRecordData.count > 0 {
            guard let contentType = self.bufferedContentType else {
                fatalError()
            }
            
            messageBody = self.bufferedRecordData
            contentTypeFromRecord = contentType
        }
        else {
            guard let (contentType, data) = try self.readRecordData() else {
                return nil
            }
            
            contentTypeFromRecord = contentType
            messageBody = data
        }
        
        switch (contentTypeFromRecord)
        {
        case .changeCipherSpec:
            return TLSChangeCipherSpec(inputStream: BinaryInputStream(messageBody), context: self.connection!)
            
        case .alert:
            return TLSAlertMessage.alertFromData(messageBody, context: self.connection!)
            
        case .handshake:
            let result = TLSHandshakeMessage.handshakeMessageFromData(messageBody, context: self.connection!)
            
            switch result {
            case .message(let message, let excessData):
                self.bufferedRecordData = excessData
                self.bufferedContentType = contentTypeFromRecord
                
                return message
                
            case .notEnoughData:
                guard let (contentType, recordData) = try self.readRecordData() else {
                    return nil
                }

                guard contentType == contentTypeFromRecord else {
                    throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
                }
                
                self.bufferedRecordData = messageBody + recordData
                self.bufferedContentType = contentType

                return nil
                
            case .error:
                if contentTypeFromRecord == .handshake {
                    throw TLSError.alert(alert: .handshakeFailure, alertLevel: .fatal)
                }
                
                throw TLSError.alert(alert: .unexpectedMessage, alertLevel: .fatal)
            }
            
        case .applicationData:
            return TLSApplicationData(applicationData: messageBody)
        }
    }

    func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8] {
        fatalError("sendData not implemented")
    }

    func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8]) {
        fatalError("decryptMessageBody not implemented")
    }
}
