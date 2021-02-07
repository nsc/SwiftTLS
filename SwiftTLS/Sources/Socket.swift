//
//  Socket.swift
//
//  Created by Nico Schmidt on 17.02.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public enum SocketError : CustomStringConvertible, Error {
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
    var isReadyToRead: Bool { get }
    func read(count : Int) throws -> [UInt8]
    func write(_ data : [UInt8]) throws
    func close()
}

extension SocketProtocol
{
    func readData(count: Int) throws -> [UInt8] {
        return try self.read(count: count)
    }
    
    func writeData(_ data: [UInt8]) throws {
        try self.write(data)
    }
}

public protocol ClientSocketProtocol : SocketProtocol
{
    func connect(_ address : IPAddress) throws
}

public protocol ServerSocketProtocol : SocketProtocol
{
    func listen(on address: IPAddress) throws
    func acceptConnection() throws -> SocketProtocol
}

public extension SocketProtocol
{
    func write(_ string : String) throws {
        let uint8BufferPointer = string.utf8CString.withUnsafeBufferPointer({ (buf) -> UnsafeBufferPointer<UInt8> in
            let ptr = UnsafeRawPointer(buf.baseAddress)!.assumingMemoryBound(to: UInt8.self)
            return UnsafeBufferPointer<UInt8>(start: ptr, count: buf.count)
        })
        
        let data = Array(uint8BufferPointer)

        try self.write(data)
    }
}

class Socket : SocketProtocol
{
    var _readBuffer : [UInt8] = [UInt8](repeating: 0, count: 64 * 1024)
    
    var peerName: IPAddress? {
        guard let sock = socketDescriptor else {
            return nil
        }
        
        return IPv4Address.peerName(with: sock)
    }
    
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

    var isReadyToRead: Bool {
        var p = pollfd(fd: socketDescriptor!, events: Int16(POLLIN), revents: 0)
        let result = poll(&p, 1, 0)
        switch result {
        case 1:
            return (p.revents & Int16(POLLIN)) != 0
            
        default:
            return false
        }
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
                    let addr = address!.socketAddress
                    bytesWrittenThisTurn = currentSlice.withUnsafeBufferPointer {
                        (buffer : UnsafeBufferPointer<UInt8>) -> Int in
                        let bufferPointer = buffer.baseAddress
                        return addr.withSocketAddress {sendto(socket, bufferPointer, currentSlice.count, Int32(0), $0, addr.length) }
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
        guard let socket = self.socketDescriptor else {
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
            #if os(Linux)
            _ = Glibc.close(socket)
            #else
            _ = Darwin.close(socket)
            #endif

            socketDescriptor = nil
        }
    }
    
    func _read(_ socket: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int
    {
        #if os(Linux)
        return Glibc.read(socket, buffer, count)
        #else
        return Darwin.read(socket, buffer, count)
        #endif
    }
    
    func _write(_ socket: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int
    {
        #if os(Linux)
        return Glibc.write(socket, buffer, count)
        #else
        return Darwin.write(socket, buffer, count)
        #endif
    }
}

extension Socket : ClientSocketProtocol
{
    func connect(_ address : IPAddress) throws
    {
        try self._connect(address)
    }
    
    func _connect(_ address : IPAddress) throws
    {
        if (socketDescriptor == nil) {
            socketDescriptor = createSocket(address.socketAddress.family)
            if (socketDescriptor == nil) {
                throw SocketError.posixError(errno: errno)
            }
        }
        
        let socket = socketDescriptor!
        
        var sockaddr = address.socketAddress
        let status = sockaddr.withSocketAddress { sockaddrPointer -> Int in
            #if os(Linux)
            return Int(Glibc.connect(socket, sockaddrPointer, sockaddr.length))
            #else
            return Int(Darwin.connect(socket, sockaddrPointer, sockaddr.length))
            #endif
        }
        
        if status < 0
        {
            throw SocketError.posixError(errno: errno)
        }
    }
}

extension Socket : ServerSocketProtocol
{
    func listen(on address: IPAddress) throws {
        if self.socketDescriptor != nil {
            self.close()
        }
        self.socketDescriptor = createSocket(address.socketAddress.family)
        
        guard let socket = self.socketDescriptor else {
            throw SocketError.closed
        }
        
        var sockaddr = address.socketAddress
        var result = sockaddr.withSocketAddress { sockaddrPointer -> Int in
            #if os(Linux)
            return Int(Glibc.bind(socket, sockaddrPointer, sockaddr.length))
            #else
            return Int(Darwin.bind(socket, sockaddrPointer, sockaddr.length))
            #endif
        }
        
        if result < 0 {
            throw SocketError.posixError(errno: errno)
        }
        
        #if os(Linux)
        result = Int(Glibc.listen(socket, 5))
        #else
        result = Int(Darwin.listen(socket, 5))
        #endif
        if result < 0 {
            throw SocketError.posixError(errno: errno)
        }
    }
    
    func acceptConnection() throws -> SocketProtocol
    {
        guard let socket = self.socketDescriptor else {
            throw SocketError.closed
        }
        
        #if os(Linux)
        let clientSocket = Glibc.accept(socket, nil, nil)
        #else
        let clientSocket = Darwin.accept(socket, nil, nil)
        #endif
        
        if clientSocket == Int32(-1) {
            throw SocketError.posixError(errno: errno)
        }
        
        var yes : Int32 = 1
        if setsockopt(clientSocket, Int32(IPPROTO_TCP), TCP_NODELAY, &yes, socklen_t(MemoryLayout<Int32>.size)) != 0 {
            perror("setsockopt")
        }
        
        return type(of: self).init(socketDescriptor: clientSocket)
    }
}

class TCPSocket : Socket
{
    override func createSocket(_ protocolFamily : sa_family_t) -> Int32?
    {
        #if os(Linux)
        let socketType = Int32(SOCK_STREAM.rawValue)
        #else
        let socketType = Int32(SOCK_STREAM)
        #endif
        
        let fd = socket(Int32(protocolFamily), socketType, Int32(IPPROTO_TCP))
        
        if fd < 0 {
            return nil
        }
        
        var yes : Int32 = 1
        #if os(Linux)
        
        var sigpipe = sigset_t()
        sigemptyset(&sigpipe)
        sigaddset(&sigpipe, SIGPIPE)
        
        pthread_sigmask(SIG_BLOCK, &sigpipe, nil)
        
        #else
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
        #endif
        
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        
//        var action = sigaction()
//        action.sa_handler = 1
//        sigaction(SIGPIPE, &action, nil)
        
        setsockopt(fd, Int32(IPPROTO_TCP), Int32(TCP_NODELAY), &yes, socklen_t(MemoryLayout<Int32>.size))
        if protocolFamily == PF_INET6 {
            var no : Int32 = 0
            let result = setsockopt(fd, Int32(IPPROTO_IPV6), Int32(IPV6_V6ONLY), &no, socklen_t(MemoryLayout<Int32>.size))
            print(result)
        }
        
        return fd
    }

}

class UDPSocket : Socket
{
    override func createSocket(_ protocolFamily : sa_family_t) -> Int32?
    {
        #if os(Linux)
        let socketType = Int32(SOCK_DGRAM.rawValue)
        #else
        let socketType = Int32(SOCK_DGRAM)
        #endif

        let fd = socket(Int32(protocolFamily), socketType, Int32(IPPROTO_UDP))

        if fd < 0 {
            return nil
        }
        
        return fd
    }
}
