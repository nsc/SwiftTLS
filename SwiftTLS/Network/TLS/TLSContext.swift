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

class TLSContext
{
    var protocolVersion : TLSProtocolVersion
    var negotiatedProtocolVersion : TLSProtocolVersion! = nil
    
    var state : TLSContextState = .Idle
    weak var dataProvider : TLSDataProvider!
    
    var serverKey : CryptoKey? = nil
    var clientKey : CryptoKey? = nil
    
    init(protocolVersion: TLSProtocolVersion, dataProvider : TLSDataProvider)
    {
        self.protocolVersion = protocolVersion
        self.dataProvider = dataProvider
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
            
            break
            
        case .Alert:
            break
            
        case .ApplicationData:
            break
        }
    }

    func _didReceiveHandshakeMessage(message : TLSHandshakeMessage, completionBlock: ((TLSContextError?) -> ())?)
    {
        let tlsConnectCompletionBlock = completionBlock

        self.didReceiveHandshakeMessage(message)
        
        switch (message.type)
        {
        case .Handshake(let handshakeType):
            
            switch (handshakeType)
            {
            case .ClientHello:
                break
                
            case .ServerHello:
                if self.state != .ClientHelloSent {
                    if let block = tlsConnectCompletionBlock {
                        block(TLSContextError.Error)
                        return
                    }
                }
                else {
                    self.state = .ServerHelloReceived
                    let version = (message as! TLSServerHello).version
                    println("Server wants to speak \(version)")
                }
                break
                
            case .Certificate:
                println("certificate")
                var certificate = message as! TLSCertificateMessage
                self.serverKey = certificate.publicKey
                self.sendClientKeyExchange()
                
                break
                
            case .ServerHelloDone:
                self.sendChangeCipherSpec()
                break
                
            default:
                println("unsupported handshake \(handshakeType.rawValue)")
                if let block = tlsConnectCompletionBlock {
                    block(TLSContextError.Error)
                    return
                }
            }
            
            break
            
        default:
            println("unsupported handshake \(message.type)")
            if let block = tlsConnectCompletionBlock {
                block(TLSContextError.Error)
                return
            }
        }
    }
    
    private func sendClientHello()
    {
        var clientHello = TLSClientHello(
            clientVersion: self.protocolVersion,
            random: Random(),
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_AES_256_CBC_SHA],
            compressionMethods: [.NULL])
        
        self.sendHandshakeMessage(clientHello)
    }
    
    private func sendClientKeyExchange()
    {
        if let serverKey = self.serverKey {
            var message = TLSClientKeyExchange(preMasterSecret: PreMasterSecret(clientVersion: TLSProtocolVersion.TLS_v1_2), publicKey: serverKey)

            self.sendHandshakeMessage(message)
        }
    }

    private func sendChangeCipherSpec()
    {
        var message = TLSChangeCipherSpec()
        
        self.sendMessage(message)
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

}