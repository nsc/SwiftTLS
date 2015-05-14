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
    case ClientHelloReceived
    case ServerHelloSent
    case ServerHelloReceived
    case ServerCertificateSent
    case ServerCertificateReceived
    case ServerHelloDoneSent
    case ServerHelloDoneReceived
    case ClientCertificateSent
    case ClientCertificateReceived
    case ClientKeyExchangeSent
    case ClientKeyExchangeReceived
    case ChangeCipherSpecSent
    case ChangeCipherSpecReceived
    case FinishedSent
    case FinishedReceived
    case Connected
    case CloseSent
    case CloseReceived
    case Error
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



let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
let TLSServerFinishedLabel = [UInt8]("server finished".utf8)

enum ConnectionEnd {
    case Client
    case Server
}

enum CipherType {
    case Block
    case Stream
}

enum BlockCipherMode {
    case CBC
}

enum MACAlgorithm {
    case HMAC_MD5
    case HMAC_SHA1
    case HMAC_SHA256
    case HMAC_SHA384
    case HMAC_SHA512
}

enum CipherAlgorithm
{
    case NULL
    case TRIPLE_DES
    case AES
}

enum CertificateCipherAlgorithm
{
    case RSA
    case DSS
}

enum PRFAlgorithm {
    case PRF_TLS_1_0
}



class TLSSecurityParameters
{
    var                     connectionEnd : ConnectionEnd = .Client
    var                     prfAlgorithm : PRFAlgorithm = .PRF_TLS_1_0
    var                     bulkCipherAlgorithm : CipherAlgorithm? = nil
    var                     cipherType : CipherType? = nil
    var                     encodeKeyLength : Int = 0
    var                     blockLength : Int = 0
    var                     fixedIVLength : Int = 0
    var                     recordIVLength : Int = 0
    var                     hmacDescriptor : HMACDescriptor? = nil
    var                     masterSecret : [UInt8]? = nil
    var                     clientRandom : [UInt8]? = nil
    var                     serverRandom : [UInt8]? = nil
    
    // Calculate master secret as described in RFC 2246, section 8.1, p. 46
    func calculateMasterSecret(preMasterSecret : [UInt8])
    {
        self.masterSecret = PRF(secret: preMasterSecret, label: [UInt8]("master secret".utf8), seed: self.clientRandom! + self.serverRandom!, outputLength: 48)
        println("master secret: \(hex(self.masterSecret!))")
    }
}



class TLSContext
{
    var protocolVersion : TLSProtocolVersion
    var negotiatedProtocolVersion : TLSProtocolVersion! = nil
    var cipherSuites : [CipherSuite]?
    var clientCipherSuites : [CipherSuite]?
    
    var cipherSuite : CipherSuite?
    
    var state : TLSContextState = .Idle {
        willSet {
            if !checkStateTransition(newValue) {
                fatalError("Illegal state transition")
            }
        }
    }
    
    var serverKey : CryptoKey?
    var clientKey : CryptoKey?
    
    var identity : Identity?
    
    var serverCertificates : [Certificate]?
    var clientCertificates : [Certificate]?
    
    var preMasterSecret     : [UInt8]? = nil

    var currentSecurityParameters  : TLSSecurityParameters
    var pendingSecurityParameters  : TLSSecurityParameters
    
    var handshakeMessages : [TLSHandshakeMessage]
    
    let isClient : Bool
    
    var recordLayer : TLSRecordLayer
    
    private var connectionEstablishedCompletionBlock : ((error : TLSContextError?) -> ())?
    
    init(protocolVersion: TLSProtocolVersion, dataProvider : TLSDataProvider, isClient : Bool = true)
    {
        self.protocolVersion = protocolVersion
        self.recordLayer = TLSRecordLayer(protocolVersion: protocolVersion, dataProvider: dataProvider, isClient: isClient)
        self.isClient = isClient
        self.handshakeMessages = []
        
        self.currentSecurityParameters = TLSSecurityParameters()
        self.pendingSecurityParameters = TLSSecurityParameters()
        
        self.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
    }
    
    func copy() -> TLSContext
    {
        var context = TLSContext(protocolVersion: self.protocolVersion, dataProvider: self.recordLayer.dataProvider!, isClient: self.isClient)
        
        context.cipherSuites = self.cipherSuites
        context.clientCipherSuites = self.clientCipherSuites
        context.cipherSuite = self.cipherSuite
        
        context.serverKey = self.serverKey
        context.clientKey = self.clientKey
        context.identity = self.identity
        
        context.serverCertificates = self.serverCertificates
        context.clientCertificates = self.clientCertificates
        
        
        context.preMasterSecret = self.preMasterSecret
        
        context.currentSecurityParameters = self.currentSecurityParameters
        context.pendingSecurityParameters = self.pendingSecurityParameters
        
        context.handshakeMessages = self.handshakeMessages

        return context
    }
    
    func startConnection(completionBlock : (error : TLSContextError?) -> ())
    {
        self.connectionEstablishedCompletionBlock = completionBlock
        
        self.sendClientHello()
        self.state = .ClientHelloSent
        
        self.receiveNextTLSMessage(completionBlock)
    }
    
    func acceptConnection(completionBlock : (error : TLSContextError?) -> ())
    {
        self.receiveNextTLSMessage(completionBlock)
    }
    
    func sendApplicationData(data : [UInt8], completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.recordLayer.sendData(contentType: .ApplicationData, data: data, completionBlock: completionBlock)
    }
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.recordLayer.sendMessage(message, completionBlock: completionBlock)
        self.didSendMessage(message)
    }
    
    func sendAlert(alert : TLSAlert, alertLevel : TLSAlertLevel, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        var alertMessage = TLSAlertMessage(alert: alert, alertLevel: alertLevel)
        self.recordLayer.sendMessage(alertMessage, completionBlock: completionBlock)
    }
    
    private func sendHandshakeMessage(message : TLSHandshakeMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.sendMessage(message, completionBlock: completionBlock)
        
        self.handshakeMessages.append(message)
    }
    
    func didSendMessage(message : TLSMessage)
    {
        println("did send message \(TLSMessageNameForType(message.type))")
    }
    
    func didSendHandshakeMessage(message : TLSHandshakeMessage)
    {
    }
    
    func didReceiveHandshakeMessage(message : TLSHandshakeMessage)
    {
    }
    
    func _didReceiveMessage(message : TLSMessage, completionBlock: ((TLSContextError?) -> ())?)
    {
        println("did receive message \(TLSMessageNameForType(message.type))")

        switch (message.type)
        {
        case .ChangeCipherSpec:
            self.state = .ChangeCipherSpecReceived

            self.recordLayer.activateReadEncryptionParameters()
            self.receiveNextTLSMessage(completionBlock)
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
            
            if (handshakeType != .Finished) {
                // don't add the incoming Finished message to handshakeMessages.
                // We need to verify it's data against the handshake messages before it.
                self.handshakeMessages.append(message)
            }
            
            switch (handshakeType)
            {
            case .ClientHello:
                var clientHello = (message as! TLSClientHello)
                self.pendingSecurityParameters.clientRandom = DataBuffer(clientHello.random).buffer
                self.clientCipherSuites = clientHello.cipherSuites
                
                self.cipherSuite = self.selectCipherSuite()
                
                if let cipherSuite = self.cipherSuite {
                    self.sendServerHello()
                    self.state = .ServerHelloSent
                    
                    self.sendCertificate()
                    self.state = .ServerCertificateSent
                    
                    self.sendServerHelloDone()
                    self.state = .ServerHelloDoneSent
                }
                else {
                    self.sendAlert(.HandshakeFailure, alertLevel: .Fatal, completionBlock: nil)
                }

            case .ServerHello:
                self.state = .ServerHelloReceived
                var serverHello = message as! TLSServerHello
                let version = serverHello.version
                println("Server wants to speak \(version)")
                
                self.recordLayer.protocolVersion = version
                
                self.pendingSecurityParameters.serverRandom = DataBuffer(serverHello.random).buffer
                self.preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: self.protocolVersion)).buffer
                self.setPendingSecurityParametersForCipherSuite(serverHello.cipherSuite)
                self.recordLayer.pendingSecurityParameters = self.pendingSecurityParameters
            
            case .Certificate:
                println("certificate")
                self.state = isClient ? .ServerCertificateReceived : .ClientCertificateReceived
                var certificateMessage = message as! TLSCertificateMessage
                self.serverCertificates = certificateMessage.certificates
                self.serverKey = certificateMessage.publicKey
                
            case .ServerHelloDone:
                self.state = .ServerHelloDoneReceived

                self.sendClientKeyExchange()
                self.state = .ClientKeyExchangeSent
                
                self.sendChangeCipherSpec()
                self.state = .ChangeCipherSpecSent

                self.sendFinished()
                self.state = .FinishedSent
                
            case .ClientKeyExchange:
                self.state = .ClientKeyExchangeReceived
                
                var clientKeyExchange = message as! TLSClientKeyExchange
                var encryptedPreMasterSecret = clientKeyExchange.encryptedPreMasterSecret
                self.identity!.privateKey.decrypt(encryptedPreMasterSecret)
                
            case .Finished:
                self.state = .FinishedReceived

                if (self.verifyFinishedMessage(message as! TLSFinished, isClient: !self.isClient)) {
                    println("Finished verified.")
                    if let connectionEstablishedBlock = self.connectionEstablishedCompletionBlock {
                        connectionEstablishedBlock(error: nil)
                    }
                }
                else {
                    println("Error: could not verify Finished message.")
                }
                
            default:
                println("unsupported handshake \(handshakeType.rawValue)")
                if let block = tlsConnectCompletionBlock {
                    block(TLSContextError.Error)
                }
            }
            
        default:
            println("unsupported handshake \(message.type)")
            if let block = tlsConnectCompletionBlock {
                block(TLSContextError.Error)

                break SWITCH
            }
        }
        
        self.didReceiveHandshakeMessage(message)
        
        switch (message.type)
        {
        case .Handshake(let handshakeType):
            if handshakeType != .Finished {
                self.receiveNextTLSMessage(completionBlock)
            }
            
        default:
            break
        }
    }
    
    func sendClientHello()
    {
        var clientHelloRandom = Random()
        var clientHello = TLSClientHello(
            clientVersion: self.protocolVersion,
            random: clientHelloRandom,
            sessionID: nil,
            cipherSuites: self.cipherSuites!,
//            cipherSuites: [.TLS_RSA_WITH_NULL_SHA],
            compressionMethods: [.NULL])
        
        self.pendingSecurityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
        self.sendHandshakeMessage(clientHello)
    }
    
    func sendServerHello()
    {
        var serverHelloRandom = Random()
        var serverHello = TLSServerHello(
            serverVersion: self.protocolVersion,
            random: serverHelloRandom,
            sessionID: nil,
            cipherSuite: self.cipherSuite!,
            compressionMethod: .NULL)
        
        self.pendingSecurityParameters.serverRandom = DataBuffer(serverHelloRandom).buffer
        self.sendHandshakeMessage(serverHello)
    }
    
    func sendCertificate()
    {
        var certificate = self.identity!.certificate
        var certificateMessage = TLSCertificateMessage(certificates: [certificate])
        
        self.sendHandshakeMessage(certificateMessage);
    }
    
    func sendServerHelloDone()
    {
        self.sendHandshakeMessage(TLSServerHelloDone())
    }
    
    func sendClientKeyExchange()
    {
        if let serverKey = self.serverKey {
            var message = TLSClientKeyExchange(preMasterSecret: self.preMasterSecret!, publicKey: serverKey)
            self.sendHandshakeMessage(message)
        }
    }

    func sendChangeCipherSpec()
    {
        var message = TLSChangeCipherSpec()
        
        self.sendMessage(message)
        
        self.currentSecurityParameters = self.pendingSecurityParameters
        self.pendingSecurityParameters = TLSSecurityParameters()
        
        self.recordLayer.activateWriteEncryptionParameters()
    }

    func sendFinished()
    {
        var verifyData = self.verifyDataForFinishedMessage(isClient: self.isClient)
        self.sendHandshakeMessage(TLSFinished(verifyData: verifyData), completionBlock: nil)
    }

    private func verifyFinishedMessage(finishedMessage : TLSFinished, isClient: Bool) -> Bool
    {
        var verifyData = self.verifyDataForFinishedMessage(isClient: isClient)
        
        return finishedMessage.verifyData == verifyData
    }

    private func verifyDataForFinishedMessage(#isClient: Bool) -> [UInt8]
    {
        var finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        
        var handshakeData = [UInt8]()
        for message in self.handshakeMessages {
            var messageBuffer = DataBuffer()
            message.writeTo(&messageBuffer)
            
            handshakeData.extend(messageBuffer.buffer)
        }
        
        var clientHandshakeMD5  = Hash_MD5(handshakeData)
        var clientHandshakeSHA1 = Hash_SHA1(handshakeData)
        
        var d = clientHandshakeMD5 + clientHandshakeSHA1

        var verifyData = PRF(secret: self.currentSecurityParameters.masterSecret!, label: finishedLabel, seed: d, outputLength: 12)
        
        return verifyData
    }
    
    
    private func receiveNextTLSMessage(completionBlock: ((TLSContextError?) -> ())?)
    {
        let tlsConnectCompletionBlock = completionBlock
        
        self._readTLSMessage {
            (message : TLSMessage?) -> () in
            
            if let m = message {
                self._didReceiveMessage(m, completionBlock: completionBlock)
            }
        }
    }

    func readTLSMessage(completionBlock: (message : TLSMessage?) -> ())
    {
        self._readTLSMessage(completionBlock)
    }
    
    private func _readTLSMessage(completionBlock: (message : TLSMessage?) -> ())
    {
        self.recordLayer.readMessage(completionBlock: completionBlock)
    }
    
    private func setPendingSecurityParametersForCipherSuite(cipherSuite : CipherSuite)
    {
        var cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
        if let cipherDescriptor = cipherSuiteDescriptor?.bulkCipherAlgorithm {
            self.pendingSecurityParameters.bulkCipherAlgorithm  = cipherDescriptor.algorithm
            self.pendingSecurityParameters.encodeKeyLength      = cipherDescriptor.keySize
            self.pendingSecurityParameters.blockLength          = cipherDescriptor.blockSize
            self.pendingSecurityParameters.fixedIVLength        = cipherDescriptor.blockSize
            self.pendingSecurityParameters.recordIVLength       = cipherDescriptor.blockSize
            
            if let hmacDescriptor = cipherSuiteDescriptor?.hmacDescriptor {
                self.pendingSecurityParameters.hmacDescriptor     = hmacDescriptor
            }
        }
        else {
            fatalError("security parameters not set after server hello was received")
        }
        
        self.pendingSecurityParameters.calculateMasterSecret(self.preMasterSecret!)
    }
    
    func advanceState(state : TLSContextState) -> Bool
    {
        if checkStateTransition(state) {
            self.state = state
            
            return true
        }
        
        return false
    }
    
    
    func checkClientStateTransition(state : TLSContextState) -> Bool
    {
        switch (self.state)
        {
        case .Idle where state == .ClientHelloSent:
            return true
            
        case .ClientHelloSent where state == .ServerHelloReceived:
            return true
            
        case .ServerHelloReceived where state == .ServerCertificateReceived:
            return true
            
        case .ServerCertificateReceived where state == .ServerHelloDoneReceived:
            return true
            
        case .ServerHelloDoneReceived where state == .ClientKeyExchangeSent:
            return true
            
        case .ClientKeyExchangeSent where state == .ChangeCipherSpecSent:
            return true
            
        case .ChangeCipherSpecSent where state == .FinishedSent:
            return true
            
        case .FinishedSent where state == .FinishedReceived:
            return true
            
        case .FinishedReceived where state == .Connected:
            return true
            
        case .Connected where (state == .CloseReceived || state == .CloseSent):
            return true
            
        default:
            return false
        }
    }
    
    func checkServerStateTransition(state : TLSContextState) -> Bool
    {
        switch (self.state)
        {
        case .Idle where state == .ServerHelloSent:
            return true

        case .ServerHelloSent where state == .ServerCertificateSent:
            return true

        case .ServerCertificateSent where state == .ServerHelloDoneSent:
            return true

        case .ServerHelloDoneSent where state == .ClientKeyExchangeReceived:
            return true

        case .ClientKeyExchangeReceived where state == .ChangeCipherSpecReceived:
            return true

        default:
            return false
        }
    }
    
    func checkStateTransition(state : TLSContextState) -> Bool
    {
        if self.isClient {
            return checkClientStateTransition(state)
        }
        else {
            return checkServerStateTransition(state)
        }
    }
    
    func selectCipherSuite() -> CipherSuite?
    {
        for clientCipherSuite in self.clientCipherSuites! {
            for myCipherSuite in self.cipherSuites! {
                if clientCipherSuite == myCipherSuite {
                    return myCipherSuite
                }
            }
        }
        
        return nil
    }
}
