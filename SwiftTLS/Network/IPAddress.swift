//
//  IPAddress.swift
//  Chat
//
//  Created by Nico Schmidt on 09.06.14.
//  Copyright (c) 2014 Nico Schmidt. All rights reserved.
//

import Foundation

class IPAddress
{
    var port : UInt16 {
        get { return 0}
        set {}
    }
    
    var string : String? {
        get {
            return ""
        }
    }
    
    var unsafeSockAddrPointer : UnsafePointer<sockaddr> {
        get {
            return UnsafePointer<sockaddr>(nil)
        }
    }
    
    class func localAddress() -> IPAddress {
        let localAddress = IPv6Address()

        var ipv6address = sockaddr_in6()
        memset(&ipv6address, 0, sizeof(sockaddr_in6))
        ipv6address.sin6_len = UInt8(sizeof(sockaddr_in6))
        ipv6address.sin6_family = sa_family_t(AF_INET6)
        ipv6address.sin6_port = 0
        ipv6address.sin6_addr = in6addr_any
        localAddress.socketAddress = ipv6address
        
        return localAddress
    }
    
    init() {}
    
    class func addressWithString(address : String, port : Int? = nil) -> IPAddress?
    {
        if let ipv4address = IPv4Address(address) {
            if let p = port {
                ipv4address.port = UInt16(p)
            }
            return ipv4address
        }
        
        if let ipv6address = IPv6Address(address) {
            if let p = port {
                ipv6address.port = UInt16(p)
            }
            return ipv6address
        }
        
        return nil
    }
    
}

class IPv4Address : IPAddress
{
    var socketAddress = sockaddr_in()

    override var port : UInt16 {
        get {
            return CFSwapInt16BigToHost(socketAddress.sin_port)
        }
        
        set {
            socketAddress.sin_port = CFSwapInt16HostToBig(newValue)
        }
    }
    
    override init()
    {
    }
    
    init?(_ address : String)
    {
        super.init()
        
        var resultCode : Int32 = 0
        address.withCString { (p : UnsafePointer<Int8>) -> () in
            resultCode = inet_pton(AF_INET, p, &self.socketAddress.sin_addr)
            if resultCode == 1 {
                self.socketAddress.sin_family = sa_family_t(AF_INET)
                self.socketAddress.sin_len = UInt8(sizeof(sockaddr_in))
            }
        }
        
        if resultCode == 0 {
            return nil
        }
    }
    
    override var string : String?
        {
        get {
            var buffer = Array<CChar>(count: Int(INET_ADDRSTRLEN), repeatedValue: 0)
            let result = inet_ntop(AF_INET,
                &socketAddress.sin_addr,
                &buffer,
                socklen_t(INET_ADDRSTRLEN))
            
            if result != nil {
                return String.fromCString(result)
            }
            
            return nil
        }
    }
    
    override var unsafeSockAddrPointer : UnsafePointer<sockaddr> {
        get {
            return withUnsafePointer(&socketAddress) {
                ptr in
                return UnsafePointer<sockaddr>(ptr)
            }
        }
    }
}

class IPv6Address : IPAddress
{
    var socketAddress = sockaddr_in6()
    
    override var port : UInt16 {
        get {
            return CFSwapInt16BigToHost(socketAddress.sin6_port)
        }
        
        set {
            socketAddress.sin6_port = CFSwapInt16HostToBig(newValue)
        }
    }

    override init()
    {
    }

    init?(_ address : String)
    {
        super.init()
        
        var resultCode : Int32 = 0
        address.withCString { (p : UnsafePointer<Int8>) -> () in
            resultCode = inet_pton(AF_INET6, p, &self.socketAddress.sin6_addr)
            if resultCode == 1 {
                self.socketAddress.sin6_family = sa_family_t(AF_INET6)
                self.socketAddress.sin6_len = UInt8(sizeof(sockaddr_in))
            }
        }
        
        if resultCode == 0 {
            return nil
        }
    }

    override var string : String?
    {
        get {
            var buffer = Array<CChar>(count: Int(INET6_ADDRSTRLEN), repeatedValue: 0)
            let result = inet_ntop(AF_INET6,
                &socketAddress.sin6_addr,
                &buffer,
                socklen_t(INET6_ADDRSTRLEN))
            
            if result != nil {
                return String.fromCString(result)
            }
            
            return nil
        }
    }

    override var unsafeSockAddrPointer : UnsafePointer<sockaddr> {
        get {
            return withUnsafePointer(&socketAddress) {
                ptr in
                return UnsafePointer<sockaddr>(ptr)
            }
        }
    }

}
