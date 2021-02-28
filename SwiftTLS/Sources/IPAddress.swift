//
//  IPAddress.swift
//
//  Created by Nico Schmidt on 09.06.14.
//  Copyright (c) 2014 Nico Schmidt. All rights reserved.
//

import Foundation

public enum SocketAddress {
    case ipv4(sockaddr_in)
    case ipv6(sockaddr_in6)
    
    var length: socklen_t {
        switch self {
        case .ipv4(_): return socklen_t(MemoryLayout<sockaddr_in>.size)
        case .ipv6(_): return socklen_t(MemoryLayout<sockaddr_in6>.size)
        }
    }
    
    var family: sa_family_t {
        switch self {
        case .ipv4(let addr): return sa_family_t(addr.sin_family)
        case .ipv6(let addr): return sa_family_t(addr.sin6_family)
        }
    }

    func withSocketAddress<R>(_ block: (UnsafePointer<sockaddr>) -> R) -> R {
        var storage = sockaddr_storage()
        switch self {
        case .ipv4(var addr): memcpy(&storage, &addr, Int(length))
        case .ipv6(var addr): memcpy(&storage, &addr, Int(length))
        }

        return withUnsafePointer(to: storage) {
            let ptr = UnsafeRawPointer($0).bindMemory(to: sockaddr.self, capacity: 1)
            return block(ptr)
        }
    }

    var storage: sockaddr_storage {
        var storage = sockaddr_storage()
        switch self {
        case .ipv4(var addr): memcpy(&storage, &addr, Int(length))
        case .ipv6(var addr): memcpy(&storage, &addr, Int(length))
        }
        
        return storage
    }
}

public protocol IPAddress : CustomStringConvertible {
    var port : UInt16 { get set }
    var hostname : String? { get set }
    var socketAddress : SocketAddress { get }
    var sockAddrLength: socklen_t { get }
    static var anyAddress: IPAddress { get }
    static var localAddress: IPAddress { get }
}

extension IPAddress {
    
    public static var anyAddress: IPAddress {
        var ipv6address = sockaddr_in6()
        memset(&ipv6address, 0, MemoryLayout<sockaddr_in6>.size)
        ipv6address.sin6_family = sa_family_t(AF_INET6)
        ipv6address.sin6_port = 0
        ipv6address.sin6_addr = in6addr_any
        
        return IPv6Address(socketAddress: ipv6address)
    }
    
    public static var localAddress: IPAddress {
        var ipv6address = sockaddr_in6()
        memset(&ipv6address, 0, MemoryLayout<sockaddr_in6>.size)
        ipv6address.sin6_family = sa_family_t(AF_INET6)
        ipv6address.sin6_port = 0
        ipv6address.sin6_addr = in6addr_loopback
        
        return IPv6Address(socketAddress: ipv6address)
    }
    
    public static func peerName(with socket: Int32) -> IPAddress? {
        let storage = UnsafeMutablePointer<sockaddr_storage>.allocate(capacity: 1)
        
        defer {
            storage.deallocate()
        }
        
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let address = UnsafeMutableRawPointer(storage).bindMemory(to: sockaddr.self, capacity: 1)
        guard getpeername(socket, address, &length) == 0 else {
            return nil
        }
        
        switch Int32(address.pointee.sa_family) {
        case AF_INET:
            let inet4addr = UnsafeMutableRawPointer(storage).bindMemory(to: sockaddr_in.self, capacity: 1)
            
            return IPv4Address(socketAddress: inet4addr.pointee)
            
        case AF_INET6:
            let inet6addr = UnsafeMutableRawPointer(storage).bindMemory(to: sockaddr_in6.self, capacity: 1)

            return IPv6Address(socketAddress: inet6addr.pointee)
            
        default:
            return nil
        }
    }
        
    public static func addressWithString(_ hostname : String, port : UInt16? = nil) -> IPAddress?
    {
        if let ipv4address = IPv4Address(hostname, port: port) {
            return ipv4address
        }
        
        if let ipv6address = IPv6Address(hostname, port: port) {
            return ipv6address
        }
        
        var addressInfoPointer: UnsafeMutablePointer<addrinfo>? = nil
        var address : IPAddress? = hostname.utf8CString.withUnsafeBufferPointer {
            if getaddrinfo($0.baseAddress, nil, nil, &addressInfoPointer) != 0 {
                log("Error: \(String(cString: strerror(errno)))")
                return nil
            }
            
            let addressInfo = addressInfoPointer!.pointee
            switch addressInfo.ai_family
            {
            case AF_INET:
                var socketAddress = sockaddr_in()
                memcpy(&socketAddress, addressInfo.ai_addr, Int(addressInfo.ai_addrlen))
                
                return IPv4Address(socketAddress: socketAddress)

            case AF_INET6:
                var socketAddress = sockaddr_in6()
                memcpy(&socketAddress, addressInfo.ai_addr, Int(addressInfo.ai_addrlen))
                
                return IPv6Address(socketAddress: socketAddress)
                
            default:
                return nil
            }
        }
        
        if address != nil {
            if let p = port {
                address!.port = UInt16(p)
            }
            address!.hostname = hostname
        }
        
        return address
    }
    
}

public struct IPv4Address : IPAddress
{
    public var socketAddress: SocketAddress {
        .ipv4(_sockaddr)
    }
    
    public var hostname: String?
    
    private var _sockaddr: sockaddr_in = sockaddr_in()
    public var port : UInt16 {
        get {
            return UInt16(bigEndian: _sockaddr.sin_port)
        }
        
        set {
            _sockaddr.sin_port = newValue.bigEndian
        }
    }
        
    public init(socketAddress: sockaddr_in, port: UInt16? = nil)
    {
        self._sockaddr = socketAddress
        if let port = port {
            self._sockaddr.sin_port = port.bigEndian
        }
    }
    
    public init?(_ address : String, port: UInt16? = nil)
    {
        var resultCode : Int32 = 0
        address.withCString { (p : UnsafePointer<Int8>) -> () in
            resultCode = inet_pton(AF_INET, p, &_sockaddr.sin_addr)
            if resultCode == 1 {
                _sockaddr.sin_family = sa_family_t(AF_INET)
                if let port = port {
                    _sockaddr.sin_port = port.bigEndian
                }
            }
        }
        
        if resultCode == 0 {
            return nil
        }
    }
    
    public var description : String {
        get {
            var buffer = Array<CChar>(repeating: 0, count: Int(INET_ADDRSTRLEN))
            var socketAddress = self._sockaddr
            let result = inet_ntop(AF_INET,
                &socketAddress.sin_addr,
                &buffer,
                socklen_t(INET_ADDRSTRLEN))
            
            if result != nil {
                return String(cString: result!)
            }
            
            return ""
        }
    }
    
    public var sockAddrLength: socklen_t {
        return socklen_t(MemoryLayout<sockaddr_in>.size)
    }

    public var unsafeSockAddrPointer : UnsafePointer<sockaddr> {
        get {
            var socketAddress = self._sockaddr
            return withUnsafePointer(to: &socketAddress) {
                ptr in
                return UnsafeRawPointer(ptr).assumingMemoryBound(to: sockaddr.self)
            }
        }
    }
        
    public static var localAddress: IPAddress {
        
        var address = sockaddr_in()
        memset(&address, 0, MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = 0

        return IPv4Address(socketAddress: address)
    }

}

public struct IPv6Address : IPAddress
{
    public var socketAddress: SocketAddress {
        .ipv6(_sockaddr)
    }
    
    public var hostname: String?
    
    var _sockaddr = sockaddr_in6()
    
    public var port : UInt16 {
        get {
            return UInt16(bigEndian: _sockaddr.sin6_port)
        }
        
        set {
            _sockaddr.sin6_port = newValue.bigEndian
        }
    }
    
    public init(socketAddress: sockaddr_in6, port: UInt16? = nil)
    {
        self._sockaddr = socketAddress
        if let port = port {
            self._sockaddr.sin6_port = port.bigEndian
        }
    }

    public init?(_ address : String, port: UInt16? = nil)
    {
        var resultCode : Int32 = 0
        address.withCString { (p : UnsafePointer<Int8>) -> () in
            resultCode = inet_pton(AF_INET6, p, &_sockaddr.sin6_addr)
            if resultCode == 1 {
                _sockaddr.sin6_family = sa_family_t(AF_INET6)
                if let port = port {
                    _sockaddr.sin6_port = port.bigEndian
                }
            }
        }
        
        if resultCode == 0 {
            return nil
        }
    }

    public var description : String {
        get {
            var buffer = Array<CChar>(repeating: 0, count: Int(INET6_ADDRSTRLEN) + 1)
            var socketAddress = _sockaddr
            return buffer.withUnsafeMutableBytes { ptr -> String in
                let buffer = ptr.bindMemory(to: Int8.self).baseAddress
                let result = inet_ntop(AF_INET6,
                                       &socketAddress.sin6_addr,
                                       buffer,
                                       socklen_t(INET6_ADDRSTRLEN))

                if result != nil {
                    let address = String(cString: result!)
                    let mappedIPv4prefix = "::ffff:"
                    return address.hasPrefix(mappedIPv4prefix) ? String(address.dropFirst(mappedIPv4prefix.count)) : address
                }
                
                return ""
            }
        }
    }

    public var sockAddrLength: socklen_t {
        return socklen_t(MemoryLayout<sockaddr_in6>.size)
    }

    public var unsafeSockAddrPointer : UnsafePointer<sockaddr> {
        get {
            var socketAddress = self.socketAddress
            return withUnsafePointer(to: &socketAddress) {
                ptr in
                return UnsafeRawPointer(ptr).assumingMemoryBound(to: sockaddr.self)
            }
        }
    }
}
