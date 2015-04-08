//
//  TLSContext.swift
//  Chat
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum CipherSuite : UInt16 {
    case TLS_RSA_WITH_NULL_MD5 = 1
    case TLS_RSA_WITH_NULL_SHA = 2
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 3
    case TLS_RSA_WITH_RC4_128_MD5 = 4
    case TLS_RSA_WITH_RC4_128_SHA = 5
    case TLS_RSA_WITH_AES_256_CBC_SHA = 0x35
    case TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3d
}

enum CompressionMethod : UInt8 {
    case NULL = 0
}


enum TLSContextState
{
    case Idle
    case ClientHelloSent
    case ServerHelloReceived
    case ServerCertificateReceived
    case ServerHelloFinished
    case FinishSent
    case FinishReceived
    case Connected
    case CloseSent
}

enum TLSContextError
{
    case Error
}

enum TLSDataProviderError
{
}

protocol TLSDataProvider : class
{
    func writeData(data : [UInt8], completionBlock : ((TLSDataProviderError?) -> ())?)
    func readData(#count : Int, completionBlock : ((data : [UInt8]?, error : TLSDataProviderError?) -> ()))
}

private func handshakeMessageNameForType(handshakeType : TLSHandshakeType) -> String
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

private func messageNameForType(messageType : TLSMessageType) -> String
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

let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
let TLSServerFinishedLabel = [UInt8]("server finished".utf8)

class TLSContext
{
    var protocolVersion : TLSProtocolVersion
    var negotiatedProtocolVersion : TLSProtocolVersion! = nil
    
    var state : TLSContextState = .Idle
    weak var dataProvider : TLSDataProvider!
    
    var serverKey : CryptoKey? = nil
    var clientKey : CryptoKey? = nil
    
    var preMasterSecret     : [UInt8]? = nil
    var masterSecret        : [UInt8]? = nil
    var clientHelloRandom   : [UInt8]? = nil
    var serverHelloRandom   : [UInt8]? = nil
    
    var handshakeMessages : [TLSHandshakeMessage]
    
    let isClient : Bool
    
    init(protocolVersion: TLSProtocolVersion, dataProvider : TLSDataProvider, isClient : Bool = true)
    {
        self.protocolVersion = protocolVersion
        self.dataProvider = dataProvider
        self.isClient = true
        self.handshakeMessages = []
    }
    
    func startConnection(completionBlock : (error : TLSContextError?) -> ()) {
        
        self.sendClientHello()
        self.state = .ClientHelloSent
        
        self.receiveNextTLSMessage(completionBlock)
    }
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        let contentType : ContentType
        switch (message.type)
        {
        case .ChangeCipherSpec:
            contentType = .ChangeCipherSpec
            
        case .Alert:
            contentType = .Alert
            
        case .Handshake:
            contentType = .Handshake
            
        case .ApplicationData:
            contentType = .ApplicationData
        }
        
        var record = TLSRecord(contentType: contentType, body: DataBuffer(message).buffer)
        self.dataProvider.writeData(DataBuffer(record).buffer, completionBlock: completionBlock)
        self.didSendMessage(message)
    }
    
    func sendHandshakeMessage(message : TLSHandshakeMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.sendMessage(message, completionBlock: completionBlock)
        
        self.handshakeMessages.append(message)
    }
    
    func didSendMessage(message : TLSMessage)
    {
        println("did send message \(messageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(message : TLSHandshakeMessage)
    {
    }
    
    func didReceiveHandshakeMessage(message : TLSHandshakeMessage)
    {
    }
    
    func _didReceiveMessage(message : TLSMessage, completionBlock: ((TLSContextError?) -> ())?)
    {
        println("did receive message \(messageNameForType(message.type))")

        switch (message.type)
        {
        case .ChangeCipherSpec:
            break
            
        case .Handshake(let handshakeType):
            var handshakeMessage = message as! TLSHandshakeMessage
            self._didReceiveHandshakeMessage(handshakeMessage, completionBlock: completionBlock)
            
        case .Alert:
            break
            
        case .ApplicationData:
            break
        }
    }

    func _didReceiveHandshakeMessage(message : TLSHandshakeMessage, completionBlock: ((TLSContextError?) -> ())?)
    {
        let tlsConnectCompletionBlock = completionBlock

        SWITCH: switch (message.type)
        {
        case .Handshake(let handshakeType):
            
            switch (handshakeType)
            {
            case .ClientHello:
                self.clientHelloRandom = DataBuffer((message as! TLSClientHello).random).buffer
                
            case .ServerHello:
                if self.state != .ClientHelloSent {
                    if let block = tlsConnectCompletionBlock {
                        block(TLSContextError.Error)

                        break SWITCH
                    }
                }
                else {
                    self.state = .ServerHelloReceived
                    let version = (message as! TLSServerHello).version
                    println("Server wants to speak \(version)")
                    
                    self.serverHelloRandom = DataBuffer((message as! TLSServerHello).random).buffer
                }
                
            case .Certificate:
                println("certificate")
                var certificate = message as! TLSCertificateMessage
                self.serverKey = certificate.publicKey
                self.sendClientKeyExchange()
                
            case .ServerHelloDone:
                self.sendChangeCipherSpec()
                self.sendFinished()
                
            case .Finished:
                
                break
                
            default:
                println("unsupported handshake \(handshakeType.rawValue)")
                if let block = tlsConnectCompletionBlock {
                    block(TLSContextError.Error)

                    break SWITCH
                }
            }
            
        default:
            println("unsupported handshake \(message.type)")
            if let block = tlsConnectCompletionBlock {
                block(TLSContextError.Error)

                break SWITCH
            }
        }
        
        self.handshakeMessages.append(message)
        
        self.didReceiveHandshakeMessage(message)
    }
    
    private func sendClientHello()
    {
        var clientHelloRandom = Random()
        var clientHello = TLSClientHello(
            clientVersion: self.protocolVersion,
            random: clientHelloRandom,
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_AES_256_CBC_SHA],
            compressionMethods: [.NULL])
        
        self.clientHelloRandom = DataBuffer(clientHelloRandom).buffer
        self.sendHandshakeMessage(clientHello)
    }
    
    private func sendClientKeyExchange()
    {
        if let serverKey = self.serverKey {
            var preMasterSecret = PreMasterSecret(clientVersion: TLSProtocolVersion.TLS_v1_2)
            var message = TLSClientKeyExchange(preMasterSecret: preMasterSecret, publicKey: serverKey)

            self.preMasterSecret = DataBuffer(preMasterSecret).buffer
            self.sendHandshakeMessage(message)
        }
    }

    private func sendChangeCipherSpec()
    {
        var message = TLSChangeCipherSpec()
        
        self.sendMessage(message)
        
        self.masterSecret = self.calculateMasterSecret()
    }

    private func sendFinished()
    {
        var finishedLabel = self.isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
    
        var buffer = DataBuffer()
        for message in self.handshakeMessages {
            message.writeTo(&buffer)
        }
        
        var clientHandshakeMD5  = Hash_MD5(buffer.buffer)
        var clientHandshakeSHA1 = Hash_SHA1(buffer.buffer)
        
        var d = clientHandshakeMD5 + clientHandshakeSHA1
        var verifyData = PRF(secret: self.masterSecret!, label: finishedLabel, seed: d, outputLength: 12)

        self.sendHandshakeMessage(TLSFinished(verifyData: verifyData), completionBlock: nil)
    }
    
    private func receiveNextTLSMessage(completionBlock: ((TLSContextError?) -> ())?)
    {
        let tlsConnectCompletionBlock = completionBlock
        
        self.readTLSMessage {
            (message : TLSMessage?) -> () in
            
            if let m = message {
                self._didReceiveMessage(m, completionBlock: completionBlock)
            }
            
            self.receiveNextTLSMessage(tlsConnectCompletionBlock)
        }
    }
    
    private func readTLSMessage(completionBlock: (message : TLSMessage?) -> ())
    {
        let headerProbeLength = TLSRecord.headerProbeLength
        
        self.dataProvider.readData(count: headerProbeLength) { (data, error) -> () in
        
            if let header = data {
                if let (contentType, bodyLength) = TLSRecord.probeHeader(header) {
                    
                    var body : [UInt8] = []
                    
                    var recursiveBlock : ((data : [UInt8]?, error : TLSDataProviderError?) -> ())!
                    var readBlock : (data : [UInt8]?, error : TLSDataProviderError?) -> () = { (data, error) -> () in
                        
                        if let d = data {
                            body.extend(d)
                            
                            if body.count < bodyLength {
                                var rest = bodyLength - body.count
                                self.dataProvider.readData(count:rest , completionBlock: recursiveBlock)
                                return
                            }
                            else {
                                if let record = TLSRecord(inputStream: BinaryInputStream(data: header + body)) {
                                    switch (record.contentType)
                                    {
                                    case .ChangeCipherSpec:
                                        break
                                        
                                    case .Alert:
                                        var alert = TLSAlert.alertFromData(body)
                                        completionBlock(message: alert)
                                        break
                                        
                                    case .Handshake:
                                        var handshakeMessage = TLSHandshakeMessage.handshakeMessageFromData(body)
                                        completionBlock(message: handshakeMessage)
                                        break
                                        
                                    case .ApplicationData:
                                        break
                                    }
                                }
                            }
                        }
                        
                    }
                    recursiveBlock = readBlock
                    
                    self.dataProvider.readData(count: bodyLength, completionBlock: readBlock)
                }
                else {
                    fatalError("Probe failed")
                }
            }
        }
    }


    /// P_hash function as defined in RFC 2246, section 5, p. 11
    typealias HashFunction = (secret : [UInt8], data : [UInt8]) -> [UInt8]
    private func P_hash(hashFunction : HashFunction, secret : [UInt8], seed : [UInt8], var outputLength : Int) -> [UInt8]
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
    private func PRF(#secret : [UInt8], label : [UInt8], seed : [UInt8], var outputLength : Int) -> [UInt8]
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
    
    // Calculate master secret as described in RFC 2246, section 8.1, p. 46
    func calculateMasterSecret() -> [UInt8] {
        return PRF(secret: self.preMasterSecret!, label: [UInt8]("master secret".utf8), seed: self.clientHelloRandom! + self.serverHelloRandom!, outputLength: 48)
    }
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

