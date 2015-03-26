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

class TLSContext
{
    var state : TLSContextState = .Idle
    weak var dataProvider : TLSDataProvider!
    
    var serverKey : CryptoKey? = nil
    var clientKey : CryptoKey? = nil
    
    init(dataProvider : TLSDataProvider)
    {
        self.dataProvider = dataProvider
    }
    
    func startConnection(completionBlock : (error : TLSContextError?) -> ()) {
        
        self.sendClientHello()
        self.state = .ClientHelloSent
        
        self.receiveNextTLSMessage(completionBlock)
    }
    
    private func sendClientHello() {
        var clientHello = TLSClientHello(
            clientVersion: ProtocolVersion.TLS_v1_2,
            random: Random(),
            sessionID: nil,
            cipherSuites: [.TLS_RSA_WITH_AES_256_CBC_SHA],
            compressionMethods: [.NULL])
        
        var record = TLSRecord(contentType: .Handshake, body: DataBuffer(clientHello).buffer)
        self.dataProvider.writeData(DataBuffer(record).buffer, completionBlock: { (error : TLSDataProviderError?) -> () in
        })
    }
    
    private func sendClientKeyExchange() {
        if let serverKey = self.serverKey {
            var message = TLSClientKeyExchange(preMasterSecret: PreMasterSecret(clientVersion: ProtocolVersion.TLS_v1_2), publicKey: serverKey)

            var record = TLSRecord(contentType: .Handshake, body: DataBuffer(message).buffer)
            self.dataProvider.writeData(DataBuffer(record).buffer, completionBlock: { (error : TLSDataProviderError?) -> () in
            })
        }
        
    }

    private func receiveNextTLSMessage(completionBlock: ((TLSContextError?) -> ())?)
    {
        let tlsConnectCompletionBlock = completionBlock
        
        self.readTLSMessage {
            (message : TLSMessage?) -> () in
            
            if let m = message {
                switch (m.type)
                {
                case .ChangeCipherSpec:
                    break
                    
                case .Handshake(let handshakeType):
                    println("handshake type = \(handshakeType.rawValue)")
                    
                    switch (handshakeType)
                    {
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
                        println("server hello done")
                        break
                        
                    default:
                        println("unsupported handshake \(handshakeType.rawValue)")
                    }
                    break
                    
                case .Alert:
                    break
                    
                case .ApplicationData:
                    break
                }
            }
            
            self.receiveNextTLSMessage(tlsConnectCompletionBlock)
        }
    }
    
    private func readTLSMessage(completionBlock: (message : TLSMessage?) -> ()) {
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