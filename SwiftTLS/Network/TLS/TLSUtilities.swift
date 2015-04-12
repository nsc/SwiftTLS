//
//  TLSUtilities.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation



/// P_hash function as defined in RFC 2246, section 5, p. 11
typealias HashFunction = (secret : [UInt8], data : [UInt8]) -> [UInt8]
func P_hash(hashFunction : HashFunction, #secret : [UInt8], #seed : [UInt8], var #outputLength : Int) -> [UInt8]
{
    var outputData = [UInt8]()
    var A : [UInt8] = seed
    var bytesLeftToWrite = outputLength
    while (bytesLeftToWrite > 0)
    {
        A = hashFunction(secret: secret, data: A)
        var output = hashFunction(secret: secret, data: A + seed)
        var bytesFromOutput = min(bytesLeftToWrite, output.count)
        outputData.extend(output[0..<bytesFromOutput])
        
        bytesLeftToWrite -= bytesFromOutput
    }
    
    return outputData
}



/// PRF function as defined in RFC 2246, section 5, p. 12
func PRF(#secret : [UInt8], #label : [UInt8], #seed : [UInt8], var #outputLength : Int) -> [UInt8]
{
    var halfSecretLength = secret.count / 2
    var S1 : [UInt8]
    var S2 : [UInt8]
    if (secret.count % 2 == 0) {
        S1 = [UInt8](secret[0..<halfSecretLength])
        S2 = [UInt8](secret[halfSecretLength..<secret.count])
    }
    else {
        S1 = [UInt8](secret[0..<halfSecretLength + 1])
        S2 = [UInt8](secret[halfSecretLength..<secret.count])
    }
    
    assert(S1.count == S2.count)
    
    var md5data  = P_hash(HMAC_MD5,  secret: S1, seed: label + seed, outputLength: outputLength)
    var sha1data = P_hash(HMAC_SHA1, secret: S2, seed: label + seed, outputLength: outputLength)
    
    var output = [UInt8](count: outputLength, repeatedValue: 0)
    for var i = 0; i < output.count; ++i
    {
        output[i] = md5data[i] ^ sha1data[i]
    }
    
    return output
}




func HMAC_MD5(var secret : [UInt8], var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_MD5_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgMD5), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA1(var secret : [UInt8], var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA1), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA_256(var secret : [UInt8], var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA256), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func HMAC_SHA_384(var secret : [UInt8], var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA384_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CCHmac(UInt32(kCCHmacAlgSHA384), secret, secret.count, data, data.count, buffer.baseAddress)
    }
    
    return output
}



func Hash_MD5(var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_MD5_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_MD5(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA1(var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA1(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA_256(var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA256(data, CC_LONG(data.count), buffer.baseAddress)
    }
    
    return output
}



func Hash_SHA_384(var data : [UInt8]) -> [UInt8]
{
    var output = [UInt8](count: Int(CC_SHA384_DIGEST_LENGTH), repeatedValue: 0)
    output.withUnsafeMutableBufferPointer { (inout buffer : UnsafeMutableBufferPointer<UInt8>) -> () in
        CC_SHA384(data, CC_LONG(data.count), buffer.baseAddress)
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
        let handshakeMessageName : String
        switch (handshakeType)
        {
        case .HelloRequest:
            handshakeMessageName = "HelloRequest"
            
        case .ClientHello:
            handshakeMessageName = "ClientHello"
            
        case .ServerHello:
            handshakeMessageName = "ServerHello"
            
        case .Certificate:
            handshakeMessageName = "Certificate"
            
        case .ServerKeyExchange:
            handshakeMessageName = "ServerKeyExchange"
            
        case .CertificateRequest:
            handshakeMessageName = "CertificateRequest"
            
        case .ServerHelloDone:
            handshakeMessageName = "ServerHelloDone"
            
        case .CertificateVerify:
            handshakeMessageName = "CertificateVerify"
            
        case .ClientKeyExchange:
            handshakeMessageName = "ClientKeyExchange"
            
        case .Finished:
            handshakeMessageName = "Finished"
        }
        
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
    return TLSCipherDescritions[cipherSuite]
}

