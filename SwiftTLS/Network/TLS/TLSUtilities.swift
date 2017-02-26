//
//  TLSUtilities.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import CommonCrypto

public enum CompressionMethod : UInt8 {
    case null = 0
}

enum HashAlgorithm : UInt8 {
    case none   = 0
    case md5    = 1
    case sha1   = 2
    case sha224 = 3
    case sha256 = 4
    case sha384 = 5
    case sha512 = 6
    
    var macAlgorithm: MACAlgorithm {
        switch self {
        case .md5:
            return .hmac_md5
            
        case .sha1:
            return .hmac_sha1
            
        case .sha256:
            return .hmac_sha256
            
        case .sha384:
            return .hmac_sha384
            
        case .sha512:
            return .hmac_sha512
            
        default:
            fatalError("HMAC with hash function \(self) is not supported.")
        }
    }
    
    var hashLength: Int {
        return macAlgorithm.size
    }
}

enum SignatureAlgorithm : UInt8 {
    case anonymous  = 0
    case rsa        = 1
    case dsa        = 2
    case ecdsa      = 3
}

struct TLSSignedData : Streamable
{
    var hashAlgorithm : HashAlgorithm?
    var signatureAlgorithm : SignatureAlgorithm?
    
    var signature : [UInt8]
    
    init(data: [UInt8], context: TLSConnection)
    {
        if context.negotiatedProtocolVersion == .v1_2 {
            self.hashAlgorithm = context.configuration.hashAlgorithm
            self.signatureAlgorithm = context.configuration.signatureAlgorithm
        }
        
        self.signature = context.sign(data)
    }
    
    init?(inputStream : InputStreamType, context: TLSConnection)
    {
        if context.negotiatedProtocolVersion == .v1_2 {
            guard
                let rawHashAlgorithm : UInt8 = inputStream.read(),
                let hashAlgorithm = HashAlgorithm(rawValue: rawHashAlgorithm),
                let rawSignatureAlgorithm : UInt8 = inputStream.read(),
                let signatureAlgorithm = SignatureAlgorithm(rawValue: rawSignatureAlgorithm)
                else {
                    return nil
            }
            
            self.hashAlgorithm = hashAlgorithm
            self.signatureAlgorithm = signatureAlgorithm
        }
        
        if let signature : [UInt8] = inputStream.read16() {
            self.signature = signature
        }
        else {
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        if self.hashAlgorithm != nil && self.signatureAlgorithm != nil {
            target.write(self.hashAlgorithm!.rawValue)
            target.write(self.signatureAlgorithm!.rawValue)
        }
        
        target.write(UInt16(self.signature.count))
        target.write(self.signature)
    }
}

enum TLSError : Error
{
    case error(String)
    case alert(alert : TLSAlert, alertLevel : TLSAlertLevel)
}


protocol TLSDataProvider : class
{
    func writeData(_ data : [UInt8]) throws
    func readData(count : Int) throws -> [UInt8]
}

let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
let TLSServerFinishedLabel = [UInt8]("server finished".utf8)

enum ConnectionEnd {
    case client
    case server
}

enum CipherType {
    case block
    case stream
    case aead
}

enum BlockCipherMode {
    case cbc
    case gcm
}

typealias HMACFunction = (_ secret : [UInt8], _ data : [UInt8]) -> [UInt8]
enum MACAlgorithm {
    //    case null
    case hmac_md5
    case hmac_sha1
    case hmac_sha256
    case hmac_sha384
    case hmac_sha512
    
    var size: Int {
        get {
            switch self {
                //            case .null:
                //                fatalError("Null MAC has no size")
                
            case .hmac_md5:
                return Int(CC_MD5_DIGEST_LENGTH)
                
            case .hmac_sha1:
                return Int(CC_SHA1_DIGEST_LENGTH)
                
            case .hmac_sha256:
                return Int(CC_SHA256_DIGEST_LENGTH)
                
            case .hmac_sha384:
                return Int(CC_SHA384_DIGEST_LENGTH)
                
            case .hmac_sha512:
                return Int(CC_SHA512_DIGEST_LENGTH)
                
            }
        }
    }
}

enum CipherAlgorithm
{
    case null
    case aes128
    case aes256
    
    var blockSize : Int {
        get {
            switch self {
            case .null: return 0
            case .aes128: return 16
            case .aes256: return 16
            }
            
        }
    }
    
    var keySize : Int {
        get {
            switch self {
            case .null: return 0
            case .aes128: return 16
            case .aes256: return 32
            }
        }
    }
}

enum KeyExchangeAlgorithm
{
    case rsa
    case dhe
    case ecdhe
}

enum CertificateType
{
    case rsa
    case ecdsa
}

enum KeyExchange
{
    case rsa
    case dhe(PFSKeyExchange)
    case ecdhe(PFSKeyExchange)
    
    var pfsKeyExchange: PFSKeyExchange? {
        switch self {
        case .dhe(let keyExchange):
            return keyExchange

        case .ecdhe(let keyExchange):
            return keyExchange
        case .rsa:
            return nil
        }
    }
}

protocol PFSKeyExchange
{
    var publicKey: [UInt8]? {get}
    var peerPublicKey: [UInt8]? {get set}
    
    func calculateSharedSecret() -> [UInt8]?
    func createKeyPair()
}

class TLSSecurityParameters
{
    var connectionEnd : ConnectionEnd = .client
    var bulkCipherAlgorithm : CipherAlgorithm? = nil
    var blockCipherMode : BlockCipherMode? = nil
    var cipherType : CipherType = .block
    var encodeKeyLength : Int = 0
    var blockLength : Int = 0
    var fixedIVLength : Int = 0
    var recordIVLength : Int = 0
    var hmac: MACAlgorithm? = nil
    var masterSecret : [UInt8]? = nil
    var clientRandom : [UInt8]? = nil
    var serverRandom : [UInt8]? = nil
    
    // secure renegotiation support (RFC 5746)
    var isUsingSecureRenegotiation: Bool = false
    var clientVerifyData: [UInt8] = []
    var serverVerifyData: [UInt8] = []
}

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

extension BigInt {
    var hexString: String {
        return "\(self)"
    }
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
    
    case .newSessionTicket:
        messageName = "NewSessionTicket"
        
    case .endOfEarlyData:
        messageName = "EndOfEarlyData"

    case .helloRetryRequest:
        messageName = "HelloRetryRequest"
        
    case .encryptedExtensions:
        messageName = "EncryptedExtensions"
        
    case .keyUpdate:
        messageName = "KeyUpdate"
        
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
