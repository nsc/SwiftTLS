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

    func sendMessage(_ message : TLSMessage) async throws
    func sendData(contentType: ContentType, data: [UInt8]) async throws
    func readMessage() async throws -> TLSMessage

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
    
    func sendMessage(_ message : TLSMessage) async throws
    {
        let contentType = message.contentType
        let messageData = [UInt8](message, context: self.connection)
        
        try await sendData(contentType: contentType, data: messageData)
    }

    func sendData(contentType: ContentType, data: [UInt8]) async throws
    {
        if let maximumRecordSize = maximumRecordSize, maximumRecordSize < data.count {
            var start = 0
            var end = 0
            while end < data.count {
                
                start = end
                end += maximumRecordSize
                if end > data.count {
                    end = data.count
                }
                
                let recordData = try recordData(forContentType: contentType, data: [UInt8](data[start..<end]))
                try await dataProvider?.writeData(recordData)
            }
        }
        else {
            let recordData = try recordData(forContentType: contentType, data: data)
            try await dataProvider?.writeData(recordData)
        }
    }
    
    func readRecordBody(count: Int) async throws -> [UInt8]
    {
        return try await readData(count: count)
    }

    func readData(count: Int) async throws -> [UInt8] {
        if bufferedRawData.count >= count {
            let data = [UInt8](bufferedRawData[0..<count])
            bufferedRawData = [UInt8](bufferedRawData.dropFirst(count))
            
            return data
        }
        
        let data = try await dataProvider!.readData(count: count - bufferedRawData.count)
        bufferedRawData += data
        
        return try await readData(count: count)
    }
    
    private func readRecordData() async throws -> (ContentType, [UInt8])? {
        let headerProbeLength = TLSRecord.headerProbeLength
        let header = try await readData(count: headerProbeLength)
        
        guard let (contentType, bodyLength) = TLSRecord.probeHeader(header) else {
            throw TLSError.error("Probe failed with malformed header \(header)")
        }
        
        let body = try await readRecordBody(count: bodyLength)
        
        return try data(forContentType: contentType, recordData: body)
    }
    
    func readMessage() async throws -> TLSMessage {
        while true {
            if let message = try await readMessageInternal() {
                return message
            }
        }
    }
    
    func readMessageInternal() async throws -> TLSMessage? {
        var messageBody: [UInt8]
        var contentTypeFromRecord: ContentType
        if bufferedRecordData.count > 0 {
            guard let contentType = bufferedContentType else {
                fatalError()
            }
            
            messageBody = bufferedRecordData
            contentTypeFromRecord = contentType
        }
        else {
            guard let (contentType, data) = try await readRecordData() else {
                return nil
            }
            
            contentTypeFromRecord = contentType
            messageBody = data
        }
        
        switch (contentTypeFromRecord)
        {
        case .changeCipherSpec:
            return TLSChangeCipherSpec(inputStream: BinaryInputStream(messageBody), context: connection!)
            
        case .alert:
            return TLSAlertMessage.alertFromData(messageBody, context: connection!)
            
        case .handshake:
            let result = TLSHandshakeMessage.handshakeMessageFromData(messageBody, context: connection!)
            
            switch result {
            case .message(let message, let excessData):
                bufferedRecordData = excessData
                bufferedContentType = contentTypeFromRecord
                
                return message
                
            case .notEnoughData:
                guard let (contentType, recordData) = try await readRecordData() else {
                    return nil
                }

                guard contentType == contentTypeFromRecord else {
                    throw TLSError.alert(.unexpectedMessage, alertLevel: .fatal)
                }
                
                bufferedRecordData = messageBody + recordData
                bufferedContentType = contentType

                return nil
                
            case .error:
                if contentTypeFromRecord == .handshake {
                    throw TLSError.alert(.handshakeFailure, alertLevel: .fatal)
                }
                
                throw TLSError.alert(.unexpectedMessage, alertLevel: .fatal)
            }
            
        case .applicationData:
            return TLSApplicationData(applicationData: messageBody)
        }
    }

    func recordData(forContentType contentType: ContentType, data: [UInt8]) throws -> [UInt8] {
        fatalError("recordData(forContentType:, data:) not implemented")
    }

    func data(forContentType contentType: ContentType, recordData: [UInt8]) throws -> (ContentType, [UInt8]) {
        fatalError("data(forContentType contentType:, recordData:) not implemented")
    }
}
