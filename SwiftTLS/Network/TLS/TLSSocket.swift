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

protocol BinaryOutputStreamType
{
    mutating func write(data : [UInt8])
    mutating func write(data : [UInt16])
    mutating func write(data : UInt8)
    mutating func write(data : UInt16)
    mutating func write(data : UInt32)
}

protocol BinaryInputStreamType
{
    func read() -> UInt8?
    func read() -> UInt16?
    func read() -> UInt32?
    func read(length : Int) -> [UInt8]?
    func read(length : Int) -> [UInt16]?
}

protocol BinaryStreamable
{
    func writeTo<Target : BinaryOutputStreamType>(inout target: Target)
}

protocol BinaryReadable
{
    init?(inputStream : BinaryInputStreamType)
}

func writeUInt24(var target : BinaryOutputStreamType, value : Int)
{
    target.write(UInt8((value >> 16) & 0xff))
    target.write(UInt8((value >>  8) & 0xff))
    target.write(UInt8((value >>  0) & 0xff))
}

func readUInt24(inputStream : BinaryInputStreamType) -> Int?
{
    if  let a : UInt8 = inputStream.read(),
        let b : UInt8 = inputStream.read(),
        let c : UInt8 = inputStream.read()
    {
        return Int(a) << 16 + Int(b) << 8 + Int(c)
    }
    
    return nil
}

class Random : BinaryStreamable, BinaryReadable
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
    
    required init?(inputStream : BinaryInputStreamType)
    {
        if  let time : UInt32 = inputStream.read(),
            let bytes : [UInt8] = inputStream.read(Random.NumberOfRandomBytes)
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
    
    func writeTo<Target : BinaryOutputStreamType>(inout target: Target) {
        target.write(gmtUnixTime)
        target.write(randomBytes)
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