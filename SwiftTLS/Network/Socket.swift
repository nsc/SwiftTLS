//
//  Socket.swift
//
//  Created by Nico Schmidt on 17.02.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftHelper

public enum SocketError : CustomStringConvertible, ErrorProtocol {
    case posixError(errno : Int32)
    
    case closed
    
    public var description : String {
        get {
            switch (self)
            {
            case let .posixError(errno):
                return String(cString: strerror(errno))
                
            case .closed:
                return "Socket Closed"
            }
        }
    }
}

public protocol SocketProtocol
{
    func connect(_ address : IPAddress) throws
    func acceptConnection(_ address : IPAddress) throws -> SocketProtocol
    func read(count : Int) throws -> [UInt8]
    func write(_ data : [UInt8]) throws
    func close()
}

public extension SocketProtocol
{
    func write(_ string : String) throws {
        let data = Array(string.nulTerminatedUTF8)
        try self.write(data)
    }
}

class Socket : SocketProtocol
{
    var _readBuffer : [UInt8] = [UInt8](repeating: 0, count: 64 * 1024)
    
    var socketDescriptor : Int32?
    
    init()
    {
    }
    
    required init(socketDescriptor : Int32)
    {
        self.socketDescriptor = socketDescriptor
    }
    
    func createSocket(_ protocolFamily : sa_family_t) -> Int32?
    {
        return nil
    }
    
    deinit {
        self.close()
    }

    func connect(_ address : IPAddress) throws
    {
        try self._connect(address)
    }
    
    func _connect(_ address : IPAddress) throws
    {
        if (socketDescriptor == nil) {
            socketDescriptor = createSocket(address.unsafeSockAddrPointer.pointee.sa_family)
            if (socketDescriptor == nil) {
                throw SocketError.posixError(errno: errno)
            }
        }
        
        let socket = socketDescriptor!
        
        let addr = address.unsafeSockAddrPointer
        let status = Darwin.connect(socket, addr, socklen_t(addr.pointee.sa_len))

        if status < 0
        {
            throw SocketError.posixError(errno: errno)
        }
    }
    
    func acceptConnection(_ address : IPAddress) throws -> SocketProtocol
    {
        self.socketDescriptor = createSocket(address.unsafeSockAddrPointer.pointee.sa_family)
        
        guard let socket = self.socketDescriptor else {
            throw SocketError.closed
        }
        
        var result = Darwin.bind(socket, address.unsafeSockAddrPointer, socklen_t(address.unsafeSockAddrPointer.pointee.sa_len))
        if result < 0 {
            throw SocketError.posixError(errno: errno)
        }
        
        result = Darwin.listen(socket, 5)
        if result < 0 {
            throw SocketError.posixError(errno: errno)
        }
        
        let clientSocket = Darwin.accept(socket, nil, nil)
        if clientSocket == Int32(-1) {
            throw SocketError.posixError(errno: errno)
        }
        
        return self.dynamicType.init(socketDescriptor: clientSocket)
    }

    func sendTo(_ address : IPAddress?, data : [UInt8]) throws
    {
        if let socket = self.socketDescriptor {
            let numberOfBytesToWrite : Int = data.count
            var numberOfBytesWritten : Int = 0
            
            var currentSlice = data[0..<data.count]
            while numberOfBytesWritten < numberOfBytesToWrite
            {
                var bytesWrittenThisTurn : Int = 0
                if (address == nil) {
                    bytesWrittenThisTurn = self._write(socket, [UInt8](currentSlice), currentSlice.count)
                }
                else {
                    let addr = address!.unsafeSockAddrPointer
                    bytesWrittenThisTurn = currentSlice.withUnsafeBufferPointer {
                        (buffer : UnsafeBufferPointer<UInt8>) -> Int in
                        let bufferPointer = buffer.baseAddress
                        return sendto(socket, bufferPointer, currentSlice.count, Int32(0), addr, socklen_t(addr.pointee.sa_len))
                    }
                }
                
                if (bytesWrittenThisTurn < 0)
                {
                    throw SocketError.posixError(errno: errno)
                }
                else if (bytesWrittenThisTurn == 0)
                {
                    throw SocketError.closed
                }
                else
                {
                    numberOfBytesWritten += bytesWrittenThisTurn
                    
                    if numberOfBytesWritten < numberOfBytesToWrite
                    {
                        currentSlice = data[numberOfBytesWritten..<numberOfBytesToWrite]
                    }
                }
            }
        }
    }

    func write(_ data : [UInt8]) throws
    {
        try self._write(data)
    }
    
    internal func _write(_ data : [UInt8]) throws
    {
        try self.sendTo(nil, data: data)
    }

    func read(count : Int) throws -> [UInt8]
    {
        return try self._read(count: count)
    }
    
    internal func _read(count : Int) throws -> [UInt8]
    {
        guard let socket = self.socketDescriptor
            else {
                // FIXME: Introduce some sane error here
                throw SocketError.closed
        }
        var dataRead = [UInt8]()
        
        var bytesReadUntilNow = 0
        while bytesReadUntilNow < count
        {
            let bytesToReadInThisRequest = min(count - bytesReadUntilNow, self._readBuffer.count)
            let result = self._read(socket, &self._readBuffer, bytesToReadInThisRequest)
            if result < 0 {
                throw SocketError.posixError(errno: errno)
            }
            else if result == 0 {
                throw SocketError.closed
            }
            else {
                dataRead.append(contentsOf: self._readBuffer[0..<result])
                bytesReadUntilNow += result
            }
        }
        
        return dataRead
    }
    
    func close() {
        self._close()
    }
    
    internal func _close()
    {
        if let socket = socketDescriptor {            
            _ = Darwin.close(socket)
            
            socketDescriptor = nil
        }
    }
    
    func _read(_ socket: Int32, _ buffer: UnsafeMutablePointer<Void>, _ count: Int) -> Int
    {
        return Darwin.read(socket, buffer, count)
    }
    
    func _write(_ socket: Int32, _ buffer: UnsafePointer<Void>, _ count: Int) -> Int
    {
        return Darwin.write(socket, buffer, count)
    }
}

class TCPSocket : Socket
{
    override func createSocket(_ protocolFamily : sa_family_t) -> Int32?
    {
        let fd = socket(Int32(protocolFamily), SOCK_STREAM, IPPROTO_TCP)
        
        if fd < 0 {
            return nil
        }
        
        var yes : Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(sizeof(Int32.self)))
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(sizeof(Int32.self)))
        
//        var action = sigaction()
//        action.sa_handler = 1
//        sigaction(SIGPIPE, &action, nil)
        
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, socklen_t(sizeof(Int32.self)))
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, socklen_t(sizeof(Int32.self)))
        
        return fd
    }

}

class UDPSocket : Socket
{
    override func createSocket(_ protocolFamily : sa_family_t) -> Int32?
    {
        let fd = socket(Int32(protocolFamily), SOCK_DGRAM, IPPROTO_UDP)

        if fd < 0 {
            return nil
        }
        
        return fd
    }
}
