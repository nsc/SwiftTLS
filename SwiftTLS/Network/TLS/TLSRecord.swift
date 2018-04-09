//
//  TLSRecord.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum ContentType : UInt8 {
    case changeCipherSpec = 20
    case alert = 21
    case handshake = 22
    case applicationData = 23
}

let TLS_RecordHeaderLength = 5

class TLSRecord : Streamable {
    var contentType : ContentType
    var protocolVersion : TLSProtocolVersion
    var body : [UInt8]
    
    required init?(inputStream: InputStreamType) {
        
        var contentType : ContentType?
        var protocolVersion : TLSProtocolVersion?
        var body : [UInt8]?
        
        if let c : UInt8 = inputStream.read() {
            if let ct = ContentType(rawValue: c) {
                contentType = ct
            }
        }
        
        if let major: UInt8 = inputStream.read(),
           let minor: UInt8 = inputStream.read()
        {
            protocolVersion = TLSProtocolVersion(major: major, minor: minor)
        }
        
        if let bodyLength: UInt16 = inputStream.read() {
            body = inputStream.read(count: Int(bodyLength))
        }

        if  let c = contentType,
            let v = protocolVersion,
            let b = body
        {
            self.contentType = c
            self.protocolVersion = v
            self.body = b
        }
        else {            
            return nil
        }
    }
    
    init(contentType : ContentType, protocolVersion: TLSProtocolVersion, body : [UInt8])
    {
        self.contentType = contentType
        self.protocolVersion = protocolVersion
        self.body = body
    }
    
    class var headerProbeLength : Int {
        get {
            return TLS_RecordHeaderLength
        }
    }
    
    class func probeHeader(_ headerData : [UInt8]) -> (contentType: ContentType, bodyLength : Int)?
    {
        if headerData.count < TLS_RecordHeaderLength {
            return nil
        }
        
        let rawContentType = headerData[0]
        if let contentType = ContentType(rawValue: rawContentType) {
            let bodyLength = Int(headerData[3]) << 8 + Int(headerData[4])
            return (contentType, bodyLength)
        }
        
        return nil
    }
    
    class func writeRecordHeader<Target : OutputStreamType>(_ target: inout Target, contentType: ContentType, protocolVersion : TLSProtocolVersion, contentLength : Int)
    {
        target.write(contentType.rawValue)
        target.write(protocolVersion.rawValue)
        target.write(UInt16(contentLength))
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        type(of: self).writeRecordHeader(&target, contentType: self.contentType, protocolVersion: self.protocolVersion, contentLength: self.body.count)
        target.write(self.body)
    }
}
