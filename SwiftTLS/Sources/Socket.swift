//
//  Socket.swift
//
//  Created by Nico Schmidt on 17.02.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

#if os(Linux)
import SystemPackage
#else
import System
#endif

public enum SocketError : CustomStringConvertible, Error {
    case posixError(errno : Int32)
    
    case closed
    
    public var description : String {
        get {
            switch (self) {
            case let .posixError(errno):
                return String(cString: strerror(errno))
                
            case .closed:
                return "Socket Closed"
            }
        }
    }
}

public protocol SocketProtocol {
    var isReadyToRead: Bool { get }
    var isListening: Bool { get }
    func read(count: Int) async throws -> [UInt8]
    func write(_ data: [UInt8]) async throws
    func close() async
}

extension SocketProtocol {
    func readData(count: Int) async throws -> [UInt8] {
        return try await self.read(count: count)
    }
    
    func writeData(_ data: [UInt8]) async throws {
        try await self.write(data)
    }
}

public protocol ClientSocketProtocol : SocketProtocol {
    func connect(_ address : IPAddress) async throws
}

public protocol ServerSocketProtocol : SocketProtocol {
    func listen(on address: IPAddress) throws
    func acceptConnection() async throws -> SocketProtocol
}

public extension SocketProtocol {
    func write(_ string : String) async throws {
        let uint8BufferPointer = string.utf8CString.withUnsafeBufferPointer({ (buf) -> UnsafeBufferPointer<UInt8> in
            let ptr = UnsafeRawPointer(buf.baseAddress)!.assumingMemoryBound(to: UInt8.self)
            return UnsafeBufferPointer<UInt8>(start: ptr, count: buf.count)
        })
        
        let data = Array(uint8BufferPointer)

        try await write(data)
    }
}

class Socket : SocketProtocol {
    var _readBuffer : [UInt8] = [UInt8](repeating: 0, count: 64 * 1024)
    
    var peerName: IPAddress? {
        guard let sock = socketDescriptor else {
            return nil
        }
        
        return IPv4Address.peerName(with: sock.rawValue)
    }

    var socketName: IPAddress? {
        guard let sock = socketDescriptor else {
            return nil
        }
        
        return IPv4Address.socketName(with: sock.rawValue)
    }

    var socketDescriptor : FileDescriptor?
    var readDispatchSource: DispatchSourceRead?
    var writeDispatchSource: DispatchSourceWrite?
    var isReadDispatchSourceSuspended = false
    var isWriteDispatchSourceSuspended = false

    /// Is this socket being listened on
    var isListening = false
    
    init() {
    }
    
    required init(socketDescriptor : Int32) {
        self.socketDescriptor = FileDescriptor(rawValue: socketDescriptor)
    }
    
    func createSocket(_ protocolFamily : sa_family_t) -> Int32? {
        return nil
    }
    
    deinit {
        self.close()
    }

    var isReadyToRead: Bool {
        var p = pollfd(fd: socketDescriptor!.rawValue, events: Int16(POLLIN), revents: 0)
        let result = poll(&p, 1, 0)
        switch result {
        case 1:
            return (p.revents & Int16(POLLIN)) != 0
            
        default:
            return false
        }
    }
    
    func sendTo(_ address : IPAddress?, data : [UInt8]) async throws {
        if let socket = self.socketDescriptor {
            let numberOfBytesToWrite : Int = data.count
            var numberOfBytesWritten : Int = 0
            
            var currentSlice = data[0..<data.count]
            while numberOfBytesWritten < numberOfBytesToWrite {
                var bytesWrittenThisTurn : Int = 0
                if let address = address {
                    let addr = address.socketAddress
                    bytesWrittenThisTurn = currentSlice.withUnsafeBufferPointer {
                        (buffer : UnsafeBufferPointer<UInt8>) -> Int in
                        let bufferPointer = buffer.baseAddress
                        return addr.withSocketAddress { sendto(socket.rawValue, bufferPointer, currentSlice.count, Int32(0), $0, addr.length) }
                    }
                }
                else {
                    bytesWrittenThisTurn = try await _write(socket, [UInt8](currentSlice), currentSlice.count)
                }
                
                if (bytesWrittenThisTurn < 0) {
                    throw SocketError.posixError(errno: errno)
                }
                else if (bytesWrittenThisTurn == 0) {
                    throw SocketError.closed
                }
                else {
                    numberOfBytesWritten += bytesWrittenThisTurn
                    
                    if numberOfBytesWritten < numberOfBytesToWrite {
                        currentSlice = data[numberOfBytesWritten..<numberOfBytesToWrite]
                    }
                }
            }
        }
    }

    func write(_ data : [UInt8]) async throws {
        try await _write(data)
    }
    
    internal func _write(_ data : [UInt8]) async throws {
        try await sendTo(nil, data: data)
    }

    func read(count : Int) async throws -> [UInt8] {
        return try await _read(count: count)
    }
    
    internal func _read(count : Int) async throws -> [UInt8] {
        guard let socket = socketDescriptor else {
            // FIXME: Introduce some sane error here
            throw SocketError.closed
        }
        var dataRead = [UInt8]()
        
        var bytesReadUntilNow = 0
        while bytesReadUntilNow < count
        {
            let bytesToReadInThisRequest = min(count - bytesReadUntilNow, _readBuffer.count)
            var readBuffer = _readBuffer
            let result = try await _read(socket, &readBuffer, bytesToReadInThisRequest)
            if result < 0 {
                throw SocketError.posixError(errno: errno)
            }
            else if result == 0 {
                throw SocketError.closed
            }
            else {
                dataRead.append(contentsOf: readBuffer[0..<result])
                bytesReadUntilNow += result
            }
        }
        
        return dataRead
    }
    
    func close() {
        _close()
    }
    
    internal func _close() {
        if let fd = self.socketDescriptor?.rawValue {
            shutdown(fd, Int32(SHUT_RDWR))
            
            do {
                try self.socketDescriptor?.close()
            }
            catch {
                
            }
        }
    }
    
    func _read(_ socket: FileDescriptor, _ buffer: UnsafeMutableRawPointer, _ count: Int) async throws -> Int {
        try await withCheckedThrowingContinuation { continuation in
            readDispatchSource = makeSuspendedReadDispatchSource(withEventHandler: { [unowned self] in
                self.readDispatchSource?.setEventHandler(handler: {})
                self.readDispatchSource = nil
                
                do {
                    let result = try socket.read(into: UnsafeMutableRawBufferPointer(start: buffer, count: count))
                    
                    continuation.resume(returning: result)
                }
                catch {
                    continuation.resume(throwing: error)
                }
            })
            
            readDispatchSource?.resume()
        }
    }
    
    func _write(_ socket: FileDescriptor, _ buffer: UnsafeRawPointer, _ count: Int) async throws -> Int {
        try await withCheckedThrowingContinuation { continuation in
            writeDispatchSource = makeSuspendedWriteDispatchSource(withEventHandler: { [unowned self] in
                self.writeDispatchSource?.setEventHandler(handler: {})
                self.writeDispatchSource = nil
                
                do {
                    let result = try socket.write(UnsafeRawBufferPointer(start: buffer, count: count))

                    continuation.resume(returning: result)
                }
                catch {
                    continuation.resume(throwing: error)
                }
            })
            writeDispatchSource?.resume()
        }
    }
    
    func makeSuspendedReadDispatchSource(withEventHandler eventHandler: @escaping () -> ()) -> DispatchSourceRead {
        guard let fd = socketDescriptor else {
            fatalError("Error: Can't setup dispatch source without a file descriptor")
        }
        
        let readDispatchSource = DispatchSource.makeReadSource(fileDescriptor: fd.rawValue)
        readDispatchSource.suspend()
        readDispatchSource.setEventHandler(handler: eventHandler)
        readDispatchSource.activate()

        return readDispatchSource
    }
    
    func makeSuspendedWriteDispatchSource(withEventHandler eventHandler: @escaping () -> ()) -> DispatchSourceWrite {
        guard let fd = socketDescriptor else {
            fatalError("Error: Can't setup dispatch source without a file descriptor")
        }

        let writeDispatchSource = DispatchSource.makeWriteSource(fileDescriptor: fd.rawValue)
        writeDispatchSource.suspend()
        writeDispatchSource.setEventHandler(handler: eventHandler)
        writeDispatchSource.activate()
        
        return writeDispatchSource
    }
}

extension Socket : ClientSocketProtocol {
    func connect(_ address : IPAddress) async throws {
        try await self._connect(address)
    }
    
    func _connect(_ address : IPAddress) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) -> Void in
            if socketDescriptor == nil {
                let descriptor = createSocket(address.socketAddress.family)
                guard descriptor != nil else {
                    continuation.resume(throwing: SocketError.posixError(errno: errno))
                    return
                }
                socketDescriptor = FileDescriptor(rawValue: CInt(descriptor!))
            }
            
            let socket = socketDescriptor!
                        
            var sockaddr = address.socketAddress
            let status = sockaddr.withSocketAddress { sockaddrPointer -> Int in
                isBlocking = false
#if os(Linux)
                return Int(Glibc.connect(socket.rawValue, sockaddrPointer, sockaddr.length))
#else
                return Int(Darwin.connect(socket.rawValue, sockaddrPointer, sockaddr.length))
#endif
            }

            guard status == 0 || Errno(rawValue: errno) == Errno.nowInProgress else {
                continuation.resume(throwing: SocketError.posixError(errno: errno))
                return
            }
            
            writeDispatchSource = makeSuspendedWriteDispatchSource(withEventHandler: { [unowned self] in
                self.writeDispatchSource?.setEventHandler(handler: {})
                self.writeDispatchSource = nil

                self.isBlocking = true
                
                var error: Int32 = 0
                var size: socklen_t = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(socket.rawValue, SOL_SOCKET, SO_ERROR, &error, &size)
                guard error == 0 else {
                    continuation.resume(throwing: SocketError.posixError(errno: error))
                    return
                }
                
                continuation.resume()
            })
            writeDispatchSource?.resume()
        }
    }
    
    var isBlocking: Bool {
        get {
            guard let fd = socketDescriptor?.rawValue else { return true }
            
            return fcntl(fd, F_GETFL) & O_NONBLOCK != 0
        }
        set {
            guard let fd = socketDescriptor?.rawValue else { return }
            
            var flags = fcntl(fd, F_GETFL)
            flags = newValue ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK)
            _ = fcntl(fd, F_SETFL, flags)
        }
    }
}

extension Socket : ServerSocketProtocol {
    func listen(on address: IPAddress) throws {
        if self.socketDescriptor != nil {
            self.close()
        }
        self.socketDescriptor = createSocket(address.socketAddress.family).map { FileDescriptor(rawValue: $0)}
        isBlocking = false
        
        guard let socket = self.socketDescriptor?.rawValue else {
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
        result = Int(Glibc.listen(socket, 100))
        #else
        result = Int(Darwin.listen(socket, 100))
        #endif
        if result < 0 {
            throw SocketError.posixError(errno: errno)
        }
        isListening = true
    }
    
    func acceptConnection() async throws -> SocketProtocol {
        guard let socket = self.socketDescriptor?.rawValue else {
            throw SocketError.closed
        }
        
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<SocketProtocol, Error>) in
#if os(Linux)
            let clientSocket = Glibc.accept(socket, nil, nil)
#else
            let clientSocket = Darwin.accept(socket, nil, nil)
#endif
            
            guard clientSocket != Int32(-1) || Errno(rawValue: errno) == .wouldBlock else {
                continuation.resume(throwing: SocketError.posixError(errno: errno))
                return
            }
            
            readDispatchSource = makeSuspendedReadDispatchSource(withEventHandler: { [unowned self] in
                self.readDispatchSource?.setEventHandler(handler: {})
                self.readDispatchSource = nil
#if os(Linux)
                let clientSocket = Glibc.accept(socket, nil, nil)
#else
                let clientSocket = Darwin.accept(socket, nil, nil)
#endif

                guard clientSocket != Int32(-1) else {
                    continuation.resume(throwing: SocketError.posixError(errno: errno))
                    return
                }

                var yes : Int32 = 1
                if setsockopt(clientSocket, Int32(IPPROTO_TCP), TCP_NODELAY, &yes, socklen_t(MemoryLayout<Int32>.size)) != 0 {
                    perror("setsockopt")
                }
                
                continuation.resume(returning: type(of: self).init(socketDescriptor: clientSocket))
            })
            readDispatchSource?.resume()
        }
    }
}

class TCPSocket : Socket {
    override func createSocket(_ protocolFamily : sa_family_t) -> Int32? {
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
        
//        var sigpipe = sigset_t()
//        sigemptyset(&sigpipe)
//        sigaddset(&sigpipe, SIGPIPE)
//
//        pthread_sigmask(SIG_BLOCK, &sigpipe, nil)
        signal(SIGPIPE, SIG_IGN)
        
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

class UDPSocket : Socket {
    override func createSocket(_ protocolFamily : sa_family_t) -> Int32? {
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
