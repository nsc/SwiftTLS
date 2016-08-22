//
//  TLSUtilities.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import CommonCrypto

func hexDigit(_ d : UInt8) -> String
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

func hexString(_ c : UInt8) -> String
{
    return hexDigit((c & 0xf0) >> 4) + hexDigit(c & 0xf)
}

func hex(_ data : [UInt8]) -> String
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

/// XOR
func ^(lhs: [UInt8], rhs: [UInt8]) -> [UInt8]
{
    let minimum = min(rhs.count, lhs.count)
    
    var result = [UInt8](repeating: 0, count: minimum)
    
    for i in 0..<minimum {
        result[i] = lhs[i] ^ rhs[i]
    }
    
    return result
}

func xorBy(_ array : inout [UInt8], _ other : [UInt8]) {
    let minimum = min(array.count, other.count)
    
    for i in 0..<minimum {
        array[i] ^= other[i]
    }
}

/// P_hash function as defined in RFC 2246, section 5, p. 11
func P_hash(_ hmacFunction : HMACFunction, secret : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
{
    var outputData = [UInt8]()
    var A : [UInt8] = seed
    var bytesLeftToWrite = outputLength
    while (bytesLeftToWrite > 0)
    {
        A = hmacFunction(secret, A)
        var output = hmacFunction(secret, A + seed)
        let bytesFromOutput = min(bytesLeftToWrite, output.count)
        outputData.append(contentsOf: output[0..<bytesFromOutput])
        
        bytesLeftToWrite -= bytesFromOutput
    }
    
    return outputData
}



func HMAC_MD5(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgMD5), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA1(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA1), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA256(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA256), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA384(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA384), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA512(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA512), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func Hash_MD5(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_MD5(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA1(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA1(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA224(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA224(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA256(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA256(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA384(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA384(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA512(_ data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    output.withUnsafeMutableBufferPointer { (buffer : inout UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA512(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}


func TLSHandshakeMessageNameForType(_ handshakeType : TLSHandshakeType) -> String
{
    var messageName : String
    switch (handshakeType)
    {
    case .helloRequest:
        messageName = "HelloRequest"
        
    case .clientHello:
        messageName = "ClientHello"
        
    case .serverHello:
        messageName = "ServerHello"
        
    case .certificate:
        messageName = "Certificate"
        
    case .serverKeyExchange:
        messageName = "ServerKeyExchange"
        
    case .certificateRequest:
        messageName = "CertificateRequest"
        
    case .serverHelloDone:
        messageName = "ServerHelloDone"
        
    case .certificateVerify:
        messageName = "CertificateVerify"
        
    case .clientKeyExchange:
        messageName = "ClientKeyExchange"
        
    case .finished:
        messageName = "Finished"
        
    case .certificateURL:
        messageName = "CertificateURL"
        
    case .certificateStatus:
        messageName = "CertificateStatus"
    }
    
    return messageName
}



func TLSMessageNameForType(_ messageType : TLSMessageType) -> String
{
    var messageName : String
    switch (messageType)
    {
    case .changeCipherSpec:
        messageName = "ChangeCipherSpec"
        
    case .handshake(let handshakeType):
        let handshakeMessageName = TLSHandshakeMessageNameForType(handshakeType)
        messageName = "Handshake(\(handshakeMessageName))"
        
    case .alert(let alertLevel, let alertDescription):
        let alertLevelString : String
        let alertDescriptionString : String
        
        switch (alertDescription)
        {
        case .closeNotify:
            alertDescriptionString = "CloseNotify"
            
        case .unexpectedMessage:
            alertDescriptionString = "UnexpectedMessage"
            
        case .badRecordMAC:
            alertDescriptionString = "BadRecordMAC"
            
        case .decryptionFailed:
            alertDescriptionString = "DecryptionFailed"
            
        case .recordOverflow:
            alertDescriptionString = "RecordOverflow"
            
        case .decompressionFailure:
            alertDescriptionString = "DecompressionFailure"
            
        case .handshakeFailure:
            alertDescriptionString = "HandshakeFailure"
            
        case .noCertificate:
            alertDescriptionString = "NoCertificate"
            
        case .badCertificate:
            alertDescriptionString = "BadCertificate"
            
        case .unsupportedCertificate:
            alertDescriptionString = "UnsupportedCertificate"
            
        case .certificateRevoked:
            alertDescriptionString = "CertificateRevoked"
            
        case .certificateExpired:
            alertDescriptionString = "CertificateExpired"
            
        case .certificateUnknown:
            alertDescriptionString = "CertificateUnknown"
            
        case .illegalParameter:
            alertDescriptionString = "IllegalParameter"
            
        case .unknownCA:
            alertDescriptionString = "UnknownCA"
            
        case .accessDenied:
            alertDescriptionString = "AccessDenied"
            
        case .decodeError:
            alertDescriptionString = "DecodeError"
            
        case .decryptError:
            alertDescriptionString = "DecryptError"
            
        case .exportRestriction:
            alertDescriptionString = "ExportRestriction"
            
        case .protocolVersion:
            alertDescriptionString = "ProtocolVersion"
            
        case .insufficientSecurity:
            alertDescriptionString = "InsufficientSecurity"
            
        case .internalError:
            alertDescriptionString = "InternalError"
            
        case .userCancelled:
            alertDescriptionString = "UserCancelled"
            
        case .noRenegotiation:
            alertDescriptionString = "NoRenegotiation"
            
        case .unsupportedExtension:
            alertDescriptionString = "UnsupportedExtension"
            
        case .certificateUnobtainable:
            alertDescriptionString = "CertificateUnobtainable"

        case .unrecognizedName:
            alertDescriptionString = "UnrecognizedName"

        case .badCertificateStatusResponse:
            alertDescriptionString = "BadCertificateStatusResponse"

        case .badCertificateHashValue:
            alertDescriptionString = "BadCertificateHashValue"

        }
        
        switch (alertLevel)
        {
        case .warning:
            alertLevelString = "Warning"
            
        case .fatal:
            alertLevelString = "Fatal"
        }
        
        messageName = "Alert(\(alertLevelString), \(alertDescriptionString))"
        
    case .applicationData:
        messageName = "ApplicationData"
        
    }
    
    return messageName
}

func TLSCipherSuiteDescriptorForCipherSuite(_ cipherSuite : CipherSuite) -> CipherSuiteDescriptor?
{
    guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptionDictionary[cipherSuite] else {
//        fatalError("Unknown cipher suite")
        return nil
    }
    
    return cipherSuiteDescriptor
}

public extension String {
    static func fromUTF8Bytes(_ bytes : [UInt8]) -> String? {
        let buffer = UnsafeBufferPointer(start: bytes, count: bytes.count)
        var string  = ""
        let hadError = transcode(buffer.makeIterator(), from: UTF8.self, to: UTF32.self, stoppingOnError: false) { string.append(Character(UnicodeScalar($0)!)) }
        
        if !hadError {
            return string
        }
        
        return nil
    }
}
