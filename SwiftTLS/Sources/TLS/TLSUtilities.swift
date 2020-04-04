//
//  TLSUtilities.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09/04/15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public enum CompressionMethod : UInt8 {
    case null = 0
}

public enum HashAlgorithm : UInt8 {
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
    
    typealias HashFunction = ([UInt8]) -> [UInt8]
    var hashFunction: HashFunction {
        switch self {
        case .sha256:
            return Hash_SHA256
            
        case .sha384:
            return Hash_SHA384
            
        default:
            fatalError("Unsupported hash function \(self)")
        }
    }

    var oid: OID {
        switch self
        {
        case .sha1:
            return OID.sha1
            
        case .sha256:
            return OID.sha256
            
        default:
            fatalError("Unsupported hash algorithm \(self)")
        }
    }
    
    init?(oid: OID)
    {
        switch oid
        {
        case .sha256:
            self = .sha256
            
        default:
            return nil
        }
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
    
    init(data: [UInt8], context: TLSConnection) throws
    {
        if context.negotiatedProtocolVersion == .v1_2 {
            self.hashAlgorithm = context.configuration.hashAlgorithm
            self.signatureAlgorithm = context.configuration.signatureAlgorithm
        }
        
        self.signature = try context.sign(data)
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
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        if self.hashAlgorithm != nil && self.signatureAlgorithm != nil {
            target.write(self.hashAlgorithm!.rawValue)
            target.write(self.signatureAlgorithm!.rawValue)
        }
        
        target.write(UInt16(self.signature.count))
        target.write(self.signature)
    }
}

public enum TLSError : Error
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

public enum CipherType {
    case block
    case stream
    case aead
}

public enum BlockCipherMode {
    case cbc
    case gcm
}

typealias HMACFunction = (_ secret : [UInt8], _ data : [UInt8]) -> [UInt8]
public enum MACAlgorithm {
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
                return 16
                
            case .hmac_sha1:
                return 20
                
            case .hmac_sha256:
                return 32
                
            case .hmac_sha384:
                return 48
                
            case .hmac_sha512:
                return 64
                
            }
        }
    }
    
    var hmacFunction: HMACFunction {
        switch self {
        case .hmac_md5:
            return HMAC_MD5
            
        case .hmac_sha1:
            return HMAC_SHA1
            
        case .hmac_sha256:
            return HMAC_SHA256
            
        case .hmac_sha384:
            return HMAC_SHA384
            
        case .hmac_sha512:
            return HMAC_SHA512
        }
    }
}

public enum CipherAlgorithm
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

public enum KeyExchangeAlgorithm
{
    case rsa
    case dhe
    case ecdhe
}

public enum CertificateType
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

//func hexDigit(_ d : UInt8) -> String
//{
//    switch (d & 0xf)
//    {
//    case 0:
//        return "0"
//    case 1:
//        return "1"
//    case 2:
//        return "2"
//    case 3:
//        return "3"
//    case 4:
//        return "4"
//    case 5:
//        return "5"
//    case 6:
//        return "6"
//    case 7:
//        return "7"
//    case 8:
//        return "8"
//    case 9:
//        return "9"
//    case 0xa:
//        return "A"
//    case 0xb:
//        return "B"
//    case 0xc:
//        return "C"
//    case 0xd:
//        return "D"
//    case 0xe:
//        return "E"
//    case 0xf:
//        return "F"
//
//    default:
//        return "0"
//    }
//}
//
//func hexString(_ c : UInt8) -> String
//{
//    return hexDigit((c & 0xf0) >> 4) + hexDigit(c & 0xf)
//}
//
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
//
//extension BigInt {
//    var hexString: String {
//        return "\(self)"
//    }
//}


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
        let output = hmacFunction(secret, A + seed)
        let bytesFromOutput = min(bytesLeftToWrite, output.count)
        outputData.append(contentsOf: output[0..<bytesFromOutput])
        
        bytesLeftToWrite -= bytesFromOutput
    }
    
    return outputData
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

    case .messageHash:
        messageName = "MessageHash"

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
        messageName = "\(handshakeMessageName)"
        
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
            
        case .decryptionFailed_RESERVED:
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
        
        case .missingExtension:
            alertDescriptionString = "MissingExtension"

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

        case .unknownPSKIdentity:
            alertDescriptionString = "UnknownPSKIdentity"

        case .certificateRequired:
            alertDescriptionString = "CertificateRequired"

        case .noApplicationProtocol:
            alertDescriptionString = "NoApplicationProtocol"

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
        return bytes.withUnsafeBufferPointer { buffer in
            var string  = ""
            let hadError = transcode(buffer.makeIterator(), from: UTF8.self, to: UTF32.self, stoppingOnError: false) { string.append(Character(UnicodeScalar($0)!)) }
            
            if !hadError {
                return string
            }
            
            return nil
        }
    }
}

extension UnsignedInteger where Self : FixedWidthInteger {
    static var random: Self {
        return Self(bigEndianBytes: TLSRandomBytes(count: MemoryLayout<Self>.size))!
    }
}

public func TLSFillWithRandomBytes(_ buffer: UnsafeMutableRawBufferPointer)
{
    #if os(Linux)
    struct SeedSetter {
        static let fd: Int32? = {
            let fd = open("/dev/urandom", O_RDONLY)
            guard fd >= 0 else {
                return nil
            }
            var seed: UInt32 = 0
            let seedSize = MemoryLayout<UInt32>.size
            let result = read(fd, &seed, seedSize)
            guard result == seedSize else {
                return nil
            }
            close(fd)
            
            srandom(seed)
            
            return fd
        }()
    }
    
    _ = SeedSetter.fd
    
    let uint8buffer = buffer.bindMemory(to: UInt8.self)
    for i in 0..<buffer.count {
        uint8buffer[i] = UInt8(random() & 0xff)
    }
    #else
    arc4random_buf(buffer.baseAddress, buffer.count)
    #endif
}

public func TLSRandomBytes(count: Int) -> [UInt8]
{
    var randomBytes = [UInt8](repeating: 0, count: count)
    
    randomBytes.withUnsafeMutableBytes { (buffer)  in
        TLSFillWithRandomBytes(buffer)
    }
    
    return randomBytes
}

class Random : Streamable, Equatable
{
    static let NumberOfRandomBytes = 28
    var gmtUnixTime : UInt32
    var randomBytes : [UInt8]
    
    var bytes: [UInt8] {
        return self.gmtUnixTime.bigEndianBytes + randomBytes
    }
    
    init()
    {
        randomBytes = TLSRandomBytes(count: 28)
        
        gmtUnixTime = UInt32(Date().timeIntervalSinceReferenceDate)
    }
    
    init?(_ bytes: [UInt8])
    {
        guard bytes.count == 32 else {
            return nil
        }
        
        self.gmtUnixTime = UInt32(bigEndianBytes: bytes[0..<4])!
        self.randomBytes = [UInt8](bytes[4..<32])
    }
    
    required init?(inputStream : InputStreamType)
    {
        if  let time : UInt32 = inputStream.read(),
            let bytes : [UInt8] = inputStream.read(count: Random.NumberOfRandomBytes)
        {
            self.gmtUnixTime = time
            self.randomBytes = bytes
        }
        else {
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write(gmtUnixTime)
        target.write(randomBytes)
    }
    
    static func == (lhs: Random, rhs: Random) -> Bool {
        return lhs.gmtUnixTime == rhs.gmtUnixTime && lhs.randomBytes == rhs.randomBytes
    }
}
