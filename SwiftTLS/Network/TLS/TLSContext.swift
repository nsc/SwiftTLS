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
    var                     macAlgorithm : MACAlgorithm? = nil
    var                     macLength : Int = 0
    var                     macKeyLength : Int = 0
    var                     masterSecret : [UInt8]? = nil
    var                     clientRandom : [UInt8]? = nil
    var                     serverRandom : [UInt8]? = nil
    
    // Calculate master secret as described in RFC 2246, section 8.1, p. 46
    func calculateMasterSecret(preMasterSecret : [UInt8])
    {
        self.masterSecret = PRF(secret: preMasterSecret, label: [UInt8]("master secret".utf8), seed: self.clientRandom! + self.serverRandom!, outputLength: 48)
    }
}



class TLSContext
{
    var protocolVersion : TLSProtocolVersion
    var negotiatedProtocolVersion : TLSProtocolVersion! = nil
    
    var state : TLSContextState = .Idle
    
    var serverKey : CryptoKey? = nil
    var clientKey : CryptoKey? = nil
    
    var preMasterSecret     : [UInt8]? = nil

    var currentSecurityParameters  : TLSSecurityParameters
    var pendingSecurityParameters  : TLSSecurityParameters
    
    var handshakeMessages : [TLSHandshakeMessage]
    
    let isClient : Bool
    
    var recordLayer : TLSRecordLayer
    
    init(protocolVersion: TLSProtocolVersion, dataProvider : TLSDataProvider, isClient : Bool = true)
    {
        self.protocolVersion = protocolVersion
        self.recordLayer = TLSRecordLayer(protocolVersion: protocolVersion, dataProvider: dataProvider)
        self.isClient = true
        self.handshakeMessages = []
        
        self.currentSecurityParameters = TLSSecurityParameters()
        self.pendingSecurityParameters = TLSSecurityParameters()
    }
    
    func startConnection(completionBlock : (error : TLSContextError?) -> ())
    {
        
        self.sendClientHello()
        self.state = .ClientHelloSent
        
        self.receiveNextTLSMessage(completionBlock)
    }
    
    func sendMessage(message : TLSMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
    {
        self.recordLayer.sendMessage(message, completionBlock: completionBlock)
        self.didSendMessage(message)
    }
    
    func sendHandshakeMessage(message : TLSHandshakeMessage, completionBlock : ((TLSDataProviderError?) -> ())? = nil)
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
                self.pendingSecurityParameters.clientRandom = DataBuffer((message as! TLSClientHello).random).buffer
                
            case .ServerHello:
                if self.state != .ClientHelloSent {
                    if let block = tlsConnectCompletionBlock {
                        block(TLSContextError.Error)

                        break SWITCH
                    }
                }
                else {
                    self.state = .ServerHelloReceived
                    var serverHello = message as! TLSServerHello
                    let version = serverHello.version
                    println("Server wants to speak \(version)")
                    
                    self.recordLayer.protocolVersion = version
                    
                    self.pendingSecurityParameters.serverRandom = DataBuffer(serverHello.random).buffer
                    var cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(serverHello.cipherSuite)
                    if let cipherDescriptor = cipherSuiteDescriptor?.bulkCipherAlgorithm {
                        self.pendingSecurityParameters.bulkCipherAlgorithm = cipherDescriptor.algorithm
                        self.pendingSecurityParameters.encodeKeyLength  = cipherDescriptor.keySize
                        self.pendingSecurityParameters.blockLength      = cipherDescriptor.blockSize
                        self.pendingSecurityParameters.fixedIVLength    = cipherDescriptor.blockSize
                        self.pendingSecurityParameters.recordIVLength   = cipherDescriptor.blockSize

                        if let hmacDescriptor = cipherSuiteDescriptor?.hmacDescriptor {
                            self.pendingSecurityParameters.macAlgorithm     = hmacDescriptor.algorithm
                            self.pendingSecurityParameters.macKeyLength        = hmacDescriptor.size
                            self.pendingSecurityParameters.macLength        = hmacDescriptor.size
                        }
                    }
                    else {
                        fatalError("security parameters not set after server hello was received")
                    }
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
                
                break SWITCH
                
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
        
        self.pendingSecurityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
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
        
        self.pendingSecurityParameters.calculateMasterSecret(self.preMasterSecret!)
        
        self.currentSecurityParameters = self.pendingSecurityParameters
        self.pendingSecurityParameters = TLSSecurityParameters()
        
        self.recordLayer.activateSecurityParameters(self.currentSecurityParameters)
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
        var verifyData = PRF(secret: self.currentSecurityParameters.masterSecret!, label: finishedLabel, seed: d, outputLength: 12)

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
        self.recordLayer.readMessage(completionBlock: completionBlock)
    }
}
