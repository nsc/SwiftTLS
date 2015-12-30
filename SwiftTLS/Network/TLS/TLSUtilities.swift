//
//  TLSUtilities.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import CommonCrypto

func hexDigit(d : UInt8) -> String
{
    switch (d & 0xf)
    {
    case 0:
        return "0"
    case 1:
        return "1"
    case 2:
        return "2"
    case 3:
        return "3"
    case 4:
        return "4"
    case 5:
        return "5"
    case 6:
        return "6"
    case 7:
        return "7"
    case 8:
        return "8"
    case 9:
        return "9"
    case 0xa:
        return "A"
    case 0xb:
        return "B"
    case 0xc:
        return "C"
    case 0xd:
        return "D"
    case 0xe:
        return "E"
    case 0xf:
        return "F"
        
    default:
        return "0"
    }
}

func hexString(c : UInt8) -> String
{
    return hexDigit((c & 0xf0) >> 4) + hexDigit(c & 0xf)
}

func hex(data : [UInt8]) -> String
{
    var s = ""
    for i in 0 ..< data.count {
        let c = data[i]
        if (i % 16 == 0 && i != 0) {
            s += "\n"
        }
        s += String(format: "%02x ", arguments: [c])
    }
    
    return s
}

/// P_hash function as defined in RFC 2246, section 5, p. 11
typealias HashFunction = (secret : [UInt8], data : [UInt8]) -> [UInt8]
func P_hash(hashFunction : HashFunction, secret : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
{
    var outputData = [UInt8]()
    var A : [UInt8] = seed
    var bytesLeftToWrite = outputLength
    while (bytesLeftToWrite > 0)
    {
        A = hashFunction(secret: secret, data: A)
        var output = hashFunction(secret: secret, data: A + seed)
        let bytesFromOutput = min(bytesLeftToWrite, output.count)
        outputData.appendContentsOf(output[0..<bytesFromOutput])
        
        bytesLeftToWrite -= bytesFromOutput
    }
    
    return outputData
}



func HMAC_MD5(secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_MD5_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgMD5), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA1(secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA1), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA256(secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA256), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA384(secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA384_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA384), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA512(secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA512_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA512), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func Hash_MD5(data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_MD5_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_MD5(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA1(data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA1(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA224(data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA224_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA224(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA256(data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA256(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA384(data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA384_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA384(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA512(data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA512_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA512(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}


func TLSHandshakeMessageNameForType(handshakeType : TLSHandshakeType) -> String
{
    var messageName : String
    switch (handshakeType)
    {
    case .HelloRequest:
        messageName = "HelloRequest"
        
    case .ClientHello:
        messageName = "ClientHello"
        
    case .ServerHello:
        messageName = "ServerHello"
        
    case .Certificate:
        messageName = "Certificate"
        
    case .ServerKeyExchange:
        messageName = "ServerKeyExchange"
        
    case .CertificateRequest:
        messageName = "CertificateRequest"
        
    case .ServerHelloDone:
        messageName = "ServerHelloDone"
        
    case .CertificateVerify:
        messageName = "CertificateVerify"
        
    case .ClientKeyExchange:
        messageName = "ClientKeyExchange"
        
    case .Finished:
        messageName = "Finished"
        
    case .CertificateURL:
        messageName = "CertificateURL"
        
    case .CertificateStatus:
        messageName = "CertificateStatus"
    }
    
    return messageName
}



func TLSMessageNameForType(messageType : TLSMessageType) -> String
{
    var messageName : String
    switch (messageType)
    {
    case .ChangeCipherSpec:
        messageName = "ChangeCipherSpec"
        
    case .Handshake(let handshakeType):
        let handshakeMessageName = TLSHandshakeMessageNameForType(handshakeType)
        messageName = "Handshake(\(handshakeMessageName))"
        
    case .Alert(let alertLevel, let alertDescription):
        let alertLevelString : String
        let alertDescriptionString : String
        
        switch (alertDescription)
        {
        case .CloseNotify:
            alertDescriptionString = "CloseNotify"
            
        case .UnexpectedMessage:
            alertDescriptionString = "UnexpectedMessage"
            
        case .BadRecordMAC:
            alertDescriptionString = "BadRecordMAC"
            
        case .DecryptionFailed:
            alertDescriptionString = "DecryptionFailed"
            
        case .RecordOverflow:
            alertDescriptionString = "RecordOverflow"
            
        case .DecompressionFailure:
            alertDescriptionString = "DecompressionFailure"
            
        case .HandshakeFailure:
            alertDescriptionString = "HandshakeFailure"
            
        case .NoCertificate:
            alertDescriptionString = "NoCertificate"
            
        case .BadCertificate:
            alertDescriptionString = "BadCertificate"
            
        case .UnsupportedCertificate:
            alertDescriptionString = "UnsupportedCertificate"
            
        case .CertificateRevoked:
            alertDescriptionString = "CertificateRevoked"
            
        case .CertificateExpired:
            alertDescriptionString = "CertificateExpired"
            
        case .CertificateUnknown:
            alertDescriptionString = "CertificateUnknown"
            
        case .IllegalParameter:
            alertDescriptionString = "IllegalParameter"
            
        case .UnknownCA:
            alertDescriptionString = "UnknownCA"
            
        case .AccessDenied:
            alertDescriptionString = "AccessDenied"
            
        case .DecodeError:
            alertDescriptionString = "DecodeError"
            
        case .DecryptError:
            alertDescriptionString = "DecryptError"
            
        case .ExportRestriction:
            alertDescriptionString = "ExportRestriction"
            
        case .ProtocolVersion:
            alertDescriptionString = "ProtocolVersion"
            
        case .InsufficientSecurity:
            alertDescriptionString = "InsufficientSecurity"
            
        case .InternalError:
            alertDescriptionString = "InternalError"
            
        case .UserCancelled:
            alertDescriptionString = "UserCancelled"
            
        case .NoRenegotiation:
            alertDescriptionString = "NoRenegotiation"
            
        }
        
        switch (alertLevel)
        {
        case .Warning:
            alertLevelString = "Warning"
            
        case .Fatal:
            alertLevelString = "Fatal"
        }
        
        messageName = "Alert(\(alertLevelString), \(alertDescriptionString))"
        
    case .ApplicationData:
        messageName = "ApplicationData"
        
    }
    
    return messageName
}

func TLSCipherSuiteDescriptorForCipherSuite(cipherSuite : CipherSuite) -> CipherSuiteDescriptor?
{
    guard let cipherSuiteDescriptor = TLSCipherSuiteDescritions[cipherSuite] else {
//        fatalError("Unknown cipher suite")
        return nil
    }
    
    return cipherSuiteDescriptor
}

public extension String {
    static func fromUTF8Bytes(bytes : [UInt8]) -> String? {
        let buffer = UnsafeBufferPointer(start: bytes, count: bytes.count)
        var string  = ""
        let hadError = transcode(UTF8.self, UTF32.self, buffer.generate(),
            { string.append(UnicodeScalar($0)) }, stopOnError: false)
        
        if !hadError {
            return string
        }
        
        return nil
    }
}
