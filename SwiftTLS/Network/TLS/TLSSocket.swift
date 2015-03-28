//
//  TLSSocket.swift
//  Chat
//
//  Created by Nico Schmidt on 12.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSSocketError {
    case Error
}

enum TLSProtocolVersion : UInt16, Printable {
    init?(major : UInt8, minor : UInt8)
    {
        self.init(rawValue: (UInt16(major) << 8) + UInt16(minor))
    }
    
    case TLS_v1_0 = 0x0301
    case TLS_v1_1 = 0x0302
    case TLS_v1_2 = 0x0303
    
    var description: String {
        get {
            switch self {

            case .TLS_v1_0:
                return "TLS v1.0"
            
            case .TLS_v1_1:
                return "TLS v1.1"

            case .TLS_v1_2:
                return "TLS v1.2"
            }
        }
    }
}

protocol OutputStreamType
{
    mutating func write(data : [UInt8])
}

protocol InputStreamType
{
    func read(length : Int) -> [UInt8]?
}

protocol Streamable
{
    init?(inputStream : InputStreamType)
    func writeTo<Target : OutputStreamType>(inout target: Target)
}

func write(var target : OutputStreamType, data : [UInt8]) {
    target.write(data)
}

func write(var target : OutputStreamType, data : [UInt16]) {
    for a in data {
        target.write([UInt8(a >> 8), UInt8(a & 0xff)])
    }
}

func write(var target : OutputStreamType, data : UInt8) {
    target.write([data])
}

func write(var target : OutputStreamType, data : UInt16) {
    target.write([UInt8(data >> 8), UInt8(data & 0xff)])
}

func write(var target : OutputStreamType, data : UInt32) {
    target.write([UInt8((data >> 24) & 0xff), UInt8((data >> 16) & 0xff), UInt8((data >>  8) & 0xff), UInt8((data >>  0) & 0xff)])
}

func writeUInt24(var target : OutputStreamType, value : Int)
{
    target.write([UInt8((value >> 16) & 0xff), UInt8((value >>  8) & 0xff), UInt8((value >>  0) & 0xff)])
}

func read(stream : InputStreamType, length: Int) -> [UInt8]?
{
    return stream.read(length)
}

func read(stream : InputStreamType) -> UInt8?
{
    if let a : [UInt8] = stream.read(1) {
        return a[0]
    }
    
    return nil
}

func read(stream : InputStreamType) -> UInt16?
{
    if let s : [UInt8] = stream.read(2) {
        return UInt16(s[0]) << 8 + UInt16(s[1])
    }
    
    return nil
}

func read(stream : InputStreamType) -> UInt32?
{
    if let s : [UInt8] = stream.read(4) {
        return UInt32(s[0]) << 24 + UInt32(s[1]) << 16 + UInt32(s[2]) << 8 + UInt32(s[3])
    }
    
    return nil
}

func read(stream : InputStreamType, length: Int) -> [UInt16]?
{
    if let s : [UInt8] = stream.read(length * 2) {
        var buffer = [UInt16](count:length, repeatedValue: 0)
        for var i = 0; i < length; ++i {
            buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
        }
        
        return buffer
    }
    
    return nil
}

func readUInt24(inputStream : InputStreamType) -> Int?
{
    if  let a : [UInt8] = read(inputStream, 3)
    {
        return Int(a[0]) << 16 + Int(a[1]) << 8 + Int(a[2])
    }
    
    return nil
}

class Random : Streamable
{
    static let NumberOfRandomBytes = 28
    var gmtUnixTime : UInt32
    var randomBytes : [UInt8]
    
    init()
    {
        randomBytes = [UInt8](count: 28, repeatedValue: 0)
        
        arc4random_buf(&randomBytes, 28)
        gmtUnixTime = UInt32(NSDate().timeIntervalSinceReferenceDate)
    }
    
    required init?(inputStream : InputStreamType)
    {
        if  let time : UInt32 = read(inputStream),
            let bytes : [UInt8] = read(inputStream, Random.NumberOfRandomBytes)
        {
            self.gmtUnixTime = time
            self.randomBytes = bytes
        }
        else {
            self.gmtUnixTime = 0
            self.randomBytes = []

            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        write(target, gmtUnixTime)
        write(target, randomBytes)
    }
}

class TLSSocket : TCPSocket, TLSDataProvider
{
    var context : TLSContext!
    
    init(protocolVersion : TLSProtocolVersion)
    {
        self.context = nil
        super.init()
        self.context = TLSContext(protocolVersion: protocolVersion, dataProvider: self)
    }
    
    func connect(address: IPAddress, completionBlock: ((TLSSocketError?) -> ())?) {
        let tlsConnectCompletionBlock = completionBlock

        super.connect(address, completionBlock: { (error : SocketError?) -> () in
            if error == nil {
                self.context.startConnection({ (error : TLSContextError?) -> () in
                    // TODO: map context errors to socket provider errors
                    tlsConnectCompletionBlock?(nil)
                })
            }
        })
    }
    
    func readData(#count: Int, completionBlock: ((data: [UInt8]?, error: TLSDataProviderError?) -> ())) {
        self.read(count: count) { (data, error) -> () in
            // TODO: map socket errors to data provider errors
            completionBlock(data: data, error: nil)
        }
    }
    
    func writeData(data: [UInt8], completionBlock: ((TLSDataProviderError?) -> ())?) {
        self.write(data) { (error: SocketError?) -> () in
            // TODO: map socket errors to data provider errors
            completionBlock?(nil)
        }
    }
}