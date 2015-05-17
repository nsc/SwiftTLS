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

func write(var target : OutputStreamType, data : UInt64) {
    target.write([
        UInt8((data >> 56) & 0xff), UInt8((data >> 48) & 0xff), UInt8((data >> 40) & 0xff), UInt8((data >> 32) & 0xff),
        UInt8((data >> 24) & 0xff), UInt8((data >> 16) & 0xff), UInt8((data >>  8) & 0xff), UInt8((data >>  0) & 0xff)
        ])
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

class TLSSocket : SocketProtocol, TLSDataProvider
{
    var context : TLSContext!
    
    var socket : TCPSocket?
    
    init(protocolVersion : TLSProtocolVersion, isClient: Bool = true)
    {
        self.context = nil
        self.context = TLSContext(protocolVersion: protocolVersion, dataProvider: self, isClient: isClient)
    }
    
    init(protocolVersion : TLSProtocolVersion, isClient: Bool, identity : Identity)
    {
        self.context = nil
        self.context = TLSContext(protocolVersion: protocolVersion, dataProvider: self, isClient: isClient)

        if isClient {
            self.context.identity = identity
        }
        else {
            self.context.identity = identity
        }
    }
    
    // add connect method that takes a domain name rather than an IP
    // so we can check the server certificate against that name
    func connect(address: IPAddress, completionBlock: ((SocketError?) -> ())?) {
        let tlsConnectCompletionBlock = completionBlock

        self.socket = TCPSocket()
        
        self.socket?.connect(address, completionBlock: { (error : SocketError?) -> () in
            if error == nil {
                self.context.startConnection({ (error : TLSContextError?) -> () in
                    // TODO: map context errors to socket provider errors
                    tlsConnectCompletionBlock?(nil)
                })
            }
        })
    }
    
    func listen(address : IPAddress, acceptBlock : (clientSocket : SocketProtocol?, error : SocketError?) -> ())
    {
        self.socket = TCPSocket()
        
        let tlsAcceptBlock = acceptBlock
        
        self.socket?.listen(address, acceptBlock: { (clientSocket, error) -> () in
            if let error = error {
                tlsAcceptBlock(clientSocket: nil, error: error)
                return
            }
            
            var clientTLSSocket = TLSSocket(protocolVersion: self.context.protocolVersion, isClient: false)
            clientTLSSocket.socket = clientSocket as? TCPSocket
            clientTLSSocket.context = self.context.copy()
            clientTLSSocket.context.recordLayer.dataProvider = clientTLSSocket
            
            clientTLSSocket.context.acceptConnection { (error : TLSContextError?) -> () in
                if error == nil {
                    tlsAcceptBlock(clientSocket: clientTLSSocket, error: nil)
                }
                else {
                    fatalError("Error: \(error)")
                }
            }
        })
    }
    
    func close()
    {
        self.context.sendAlert(.CloseNotify, alertLevel: .Warning) { (error : TLSDataProviderError?) -> () in
            // When the send is done, close the underlying socket
            // We might want to have an option to wait for the peer to send *its* closeNotify if it wants to
            self.socket?.close()
        }
    }
    
    func read(#count: Int, completionBlock: ((data: [UInt8]?, error: SocketError?) -> ()))
    {
        self.context.readTLSMessage { (message) -> () in
            if let message = message
            {
                switch message.type
                {
                case .ApplicationData:
                    var applicationData = (message as! TLSApplicationData).applicationData
            
                    if applicationData.count == 0 {
                        self.read(count: count, completionBlock: completionBlock)
                    }
                    else {
                        completionBlock(data: applicationData, error: nil)
                    }
                    
                default:
                    println("Error: unhandled message \(message)")
                    break
                }
            }
            else {
                println("No TLS message read.")
            }
        }
    }
    
    func readData(#count: Int, completionBlock: ((data: [UInt8]?, error: TLSDataProviderError?) -> ()))
    {
        self.socket?.read(count: count) { (data, error) -> () in
            completionBlock(data: data, error: TLSDataProviderError(socketError: error))
        }
    }
    
    func writeData(data: [UInt8], completionBlock: ((TLSDataProviderError?) -> ())? = nil)
    {
        self.socket?.write(data) { (error: SocketError?) -> () in
            completionBlock?(TLSDataProviderError(socketError: error))
        }
    }
    
    func write(data: [UInt8], completionBlock: ((SocketError?) -> ())? = nil)
    {
        self.context.sendApplicationData(data) { (error : TLSDataProviderError?) -> () in
            var socketError : SocketError? = nil
            if let error = error {
                switch error {
                case .PosixError(errno):
                    socketError = SocketError.PosixError(errno: errno)

                default:
                    break
                }
            }
            
            completionBlock?(socketError)
        }
    }
}