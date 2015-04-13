//
//  TLSRecord.swift
//  Chat
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum ContentType : UInt8 {
    case ChangeCipherSpec = 20
    case Alert = 21
    case Handshake = 22
    case ApplicationData = 23
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
        
        if let c : UInt8 = read(inputStream) {
            if let ct = ContentType(rawValue: c) {
                contentType = ct
            }
        }
        
        if let major : UInt8? = read(inputStream),
            minor : UInt8? = read(inputStream),
            v = TLSProtocolVersion(major: major!, minor: minor!)
        {
            protocolVersion = v
        }
        
        if let bodyLength : UInt16 = read(inputStream) {
            body = read(inputStream, Int(bodyLength))
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
            self.contentType = .Alert
            self.protocolVersion = .TLS_v1_0
            self.body = []
            
            return nil
        }
    }
    
    init(contentType : ContentType, protocolVersion: TLSProtocolVersion, var body : [UInt8])
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
    
    class func probeHeader(headerData : [UInt8]) -> (contentType: ContentType, bodyLength : Int)?
    {
        if headerData.count < TLS_RecordHeaderLength {
            return nil
        }
        
        var rawContentType = headerData[0]
        if let contentType = ContentType(rawValue: rawContentType) {
            var bodyLength = Int(headerData[3]) << 8 + Int(headerData[4])
            return (contentType, bodyLength)
        }
        
        return nil
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        write(target, self.contentType.rawValue)
        write(target, self.protocolVersion.rawValue)
        write(target, UInt16(self.body.count))
        write(target, self.body)
    }
}
