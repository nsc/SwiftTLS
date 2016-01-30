//
//  TLSSocket.swift
//  Chat
//
//  Created by Nico Schmidt on 12.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSSocketError : ErrorType {
    case Error
}

public enum TLSProtocolVersion : UInt16, CustomStringConvertible, Comparable {
    init?(major : UInt8, minor : UInt8)
    {
        self.init(rawValue: (UInt16(major) << 8) + UInt16(minor))
    }
    
    case TLS_v1_0 = 0x0301
    case TLS_v1_1 = 0x0302
    case TLS_v1_2 = 0x0303
    
    public var description: String {
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


public func == (lhs : TLSProtocolVersion, rhs : TLSProtocolVersion) -> Bool
{
    return lhs.rawValue == rhs.rawValue
}

public func < (lhs : TLSProtocolVersion, rhs : TLSProtocolVersion) -> Bool
{
    return lhs.rawValue < rhs.rawValue
}

protocol OutputStreamType
{
    func write(data : [UInt8])
}

protocol InputStreamType
{
    func read(count count : Int) -> [UInt8]?
}

protocol Streamable
{
    func writeTo<Target : OutputStreamType>(inout target: Target)
}

extension OutputStreamType
{
    func write(data : [UInt16]) {
        for a in data {
            self.write([UInt8(a >> 8), UInt8(a & 0xff)])
        }
    }

    func write(data : UInt8) {
        self.write([data])
    }
    
    func write(data : UInt16) {
        self.write([UInt8(data >> 8), UInt8(data & 0xff)])
    }
    
    func write(data : UInt32) {
        self.write([UInt8((data >> 24) & 0xff), UInt8((data >> 16) & 0xff), UInt8((data >>  8) & 0xff), UInt8((data >>  0) & 0xff)])
    }
    
    func write(data : UInt64) {
        self.write([
            UInt8((data >> 56) & 0xff), UInt8((data >> 48) & 0xff), UInt8((data >> 40) & 0xff), UInt8((data >> 32) & 0xff),
            UInt8((data >> 24) & 0xff), UInt8((data >> 16) & 0xff), UInt8((data >>  8) & 0xff), UInt8((data >>  0) & 0xff)
            ])
    }
    
    func writeUInt24(value : Int)
    {
        self.write([UInt8((value >> 16) & 0xff), UInt8((value >>  8) & 0xff), UInt8((value >>  0) & 0xff)])
    }
}

extension InputStreamType
{
    func read() -> UInt8?
    {
        if let a : [UInt8] = self.read(count: 1) {
            return a[0]
        }
        
        return nil
    }
    
    func read() -> UInt16?
    {
        if let s : [UInt8] = self.read(count: 2) {
            return UInt16(s[0]) << 8 + UInt16(s[1])
        }
        
        return nil
    }
    
    func read() -> UInt32?
    {
        if let s : [UInt8] = self.read(count: 4) {
            
            let a = UInt32(s[0])
            let b = UInt32(s[1])
            let c = UInt32(s[2])
            let d = UInt32(s[3])
            
            return a << 24 + b << 16 + c << 8 + d
        }
        
        return nil
    }
    
    func read(count count: Int) -> [UInt16]?
    {
        if let s : [UInt8] = self.read(count: count * 2) {
            var buffer = [UInt16](count: count, repeatedValue: 0)
            for i in 0 ..< count {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }
    
    func read(bytes bytes: Int) -> [UInt16]?
    {
        let count = bytes / 2
        if let s : [UInt8] = self.read(count: bytes) {
            var buffer = [UInt16](count: count, repeatedValue: 0)
            for i in 0 ..< count {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }

    func readUInt24() -> Int?
    {
        if  let a : [UInt8] = self.read(count: 3)
        {
            return Int(a[0]) << 16 + Int(a[1]) << 8 + Int(a[2])
        }
        
        return nil
    }
    
    func read8() -> [UInt8]?
    {
        guard
            let count : UInt8 = self.read(),
            let data : [UInt8] = self.read(count: Int(count))
            else {
                return nil
        }
        
        return data
    }

    func read16() -> [UInt8]?
    {
        guard
            let count : UInt16 = self.read(),
            let data : [UInt8] = self.read(count: Int(count))
        else {
            return nil
        }
        
        return data
    }

    func read16() -> [UInt16]?
    {
        guard
            let count : UInt16 = self.read(),
            let data : [UInt16] = self.read(bytes: Int(count))
            else {
                return nil
        }
        
        return data
    }

}

public func TLSRandomBytes(count: Int) -> [UInt8]
{
    var randomBytes = [UInt8](count: count, repeatedValue: 0)
    
    arc4random_buf(&randomBytes, count)
    
    return randomBytes
}

class Random : Streamable
{
    static let NumberOfRandomBytes = 28
    var gmtUnixTime : UInt32
    var randomBytes : [UInt8]
    
    init()
    {
        randomBytes = TLSRandomBytes(28)
        
        gmtUnixTime = UInt32(NSDate().timeIntervalSinceReferenceDate)
    }
    
    required init?(inputStream : InputStreamType)
    {
        if  let time : UInt32 = inputStream.read(),
            let bytes : [UInt8] = inputStream.read(count: Random.NumberOfRandomBytes)
        {
            self.gmtUnixTime = time
            self.randomBytes = bytes
        }
        else {
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(inout target: Target) {
        target.write(gmtUnixTime)
        target.write(randomBytes)
    }
}

public class TLSSocket : SocketProtocol, TLSDataProvider
{
    public var context : TLSContext!
    
    var socket : TCPSocket?
    
    convenience public init(protocolVersion : TLSProtocolVersion, isClient: Bool = true)
    {
        self.init(configuration: TLSConfiguration(protocolVersion: protocolVersion), isClient: isClient)
    }

    public init(configuration: TLSConfiguration, isClient: Bool = true)
    {
        self.context = TLSContext(configuration: configuration, dataProvider: self, isClient: isClient)
    }
        
    // TODO: add connect method that takes a domain name rather than an IP
    // so we can check the server certificate against that name
    public func connect(address: IPAddress) throws
    {
        self.socket = TCPSocket()
        
        try self.socket?.connect(address)
        try self.context.startConnection()
    }
    
    public func acceptConnection(address: IPAddress) throws -> SocketProtocol
    {
        self.socket = TCPSocket()
        
        let clientSocket = try self.socket?.acceptConnection(address) as! TCPSocket

        let clientTLSSocket = TLSSocket(protocolVersion: self.context.configuration.protocolVersion, isClient: false)
        clientTLSSocket.socket = clientSocket
        clientTLSSocket.context = self.context.copy(isClient: false)
        clientTLSSocket.context.recordLayer.dataProvider = clientTLSSocket
        
        try clientTLSSocket.context.acceptConnection()
        
        return clientTLSSocket
    }
    
    public func close()
    {
        do {
            try self.context.sendAlert(.CloseNotify, alertLevel: .Warning)
        }
        catch
        {
        }
        
        // When the send is done, close the underlying socket
        // We might want to have an option to wait for the peer to send *its* closeNotify if it wants to
        self.socket?.close()
    }
    
    public func read(count count: Int) throws -> [UInt8]
    {
        let message = try self.context.readTLSMessage()
        switch message.type
        {
        case .ApplicationData:
            let applicationData = (message as! TLSApplicationData).applicationData
            
            if applicationData.count == 0 {
                return try self.read(count: count)
            }
            else {
                return applicationData
            }
            
        case .Alert(let level, let alert):
            print("Alert: \(level) \(alert)")
            return []
            
        default:
            throw TLSError.Error("Error: unhandled message \(message)")
        }
    }

    func readData(count count: Int) throws -> [UInt8]
    {
        return try self.socket!.read(count: count)
    }
    
    func writeData(data: [UInt8]) throws
    {
        try self.socket?.write(data)
    }
    
    public func write(data: [UInt8]) throws
    {
        try self.context.sendApplicationData(data)
    }
}