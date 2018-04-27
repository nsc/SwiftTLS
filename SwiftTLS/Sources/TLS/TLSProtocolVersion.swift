//
//  TLSProtocolVersion.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 14.10.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

public struct TLSProtocolVersion : RawRepresentable, CustomStringConvertible, Comparable {
    public typealias RawValue = UInt16
    init(major : UInt8, minor : UInt8)
    {
        self.init(rawValue: (UInt16(major) << 8) + UInt16(minor))!
    }
    
    public init?(rawValue: UInt16)
    {
        _rawValue = rawValue
    }
    
    init?(inputStream: InputStreamType)
    {
        guard let rawSupportedVersion : UInt16 = inputStream.read() else {
            return nil
        }
        
        self.init(rawValue: rawSupportedVersion)
    }
    
    private var _rawValue: UInt16
    public var rawValue: UInt16 {
        get {
            return _rawValue
        }
    }
    
    public static let v1_0 = TLSProtocolVersion(rawValue: 0x0301)!
    public static let v1_1 = TLSProtocolVersion(rawValue: 0x0302)!
    public static let v1_2 = TLSProtocolVersion(rawValue: 0x0303)!
    // FIXME: As long as the TLS 1.3 RFC has draft status, we are using a draft version
    // number as of section 4.2.1.1.
//    public static let v1_3 = TLSProtocolVersion(rawValue: 0x7f17)! // draft-23
    public static let v1_3 = TLSProtocolVersion(rawValue: 0x7f1a)! // draft-26
//    public static let v1_3 = TLSProtocolVersion(rawValue: 0x0304)!
    
    public var description: String {
        get {
            switch self {
                
            case TLSProtocolVersion.v1_0:
                return "TLS v1.0"
                
            case TLSProtocolVersion.v1_1:
                return "TLS v1.1"
                
            case TLSProtocolVersion.v1_2:
                return "TLS v1.2"

            case TLSProtocolVersion.v1_3:
                return "TLS v1.3 draft-26"

            default:
                return "Unknown TLS version \(_rawValue >> 8).\(_rawValue & 0xff)"
            }
        }
    }
    
    public var isKnownVersion: Bool {
        get {
            switch self {
            case TLSProtocolVersion.v1_0, TLSProtocolVersion.v1_1, TLSProtocolVersion.v1_2, TLSProtocolVersion.v1_3:
                return true
            default:
                return false
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

