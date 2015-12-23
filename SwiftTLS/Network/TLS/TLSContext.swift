//
//  TLSContext.swift
//  Chat
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public enum CompressionMethod : UInt8 {
    case NULL = 0
}

enum HashAlgorithm : UInt8 {
    case none   = 0
    case MD5    = 1
    case SHA1   = 2
    case SHA224 = 3
    case SHA256 = 4
    case SHA384 = 5
    case SHA512 = 6
}

enum SignatureAlgorithm : UInt8 {
    case anonymous  = 0
    case RSA        = 1
    case DSA        = 2
    case ECDSA      = 3
}

struct TLSSignedData : Streamable
{
    var hashAlgorithm : HashAlgorithm?
    var signatureAlgorithm : SignatureAlgorithm?
    
    var signature : [UInt8]

    // FIXME: this is only needed to quiet the compiler because of the bug that you have to initialize
    // all ivars even when a failable initializer fails
    init()
    {
        self.signature = []
    }
    
    init?(inputStream : InputStreamType, context: TLSContext)
    {
        if context.negotiatedProtocolVersion == .TLS_v1_2 {
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
    
    func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        if self.hashAlgorithm != nil && self.signatureAlgorithm != nil {
            target.write(self.hashAlgorithm!.rawValue)
            target.write(self.signatureAlgorithm!.rawValue)
        }
        
        target.write(UInt16(self.signature.count))
        target.write(self.signature)
    }
}

enum TLSError : ErrorType
{
    case Error(String)
}


enum TLSDataProviderError : ErrorType
{
}



protocol TLSDataProvider : class
{
    func writeData(data : [UInt8]) throws
    func readData(count count : Int) throws -> [UInt8]
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

enum KeyExchangeAlgorithm
{
    case RSA
    case DHE_RSA
    case ECDHE_RSA
}

enum PRFAlgorithm {
    case PRF_TLS_1_0
}



class TLSSecurityParameters
{
    var connectionEnd : ConnectionEnd = .Client
    var prfAlgorithm : PRFAlgorithm = .PRF_TLS_1_0
    var bulkCipherAlgorithm : CipherAlgorithm? = nil
    var cipherType : CipherType? = nil
    var encodeKeyLength : Int = 0
    var blockLength : Int = 0
    var fixedIVLength : Int = 0
    var recordIVLength : Int = 0
    var hmacDescriptor : HMACDescriptor? = nil
    var masterSecret : [UInt8]? = nil
    var clientRandom : [UInt8]? = nil
    var serverRandom : [UInt8]? = nil
}



protocol TLSContextStateMachine
{
    func didSendMessage(message : TLSMessage) throws
    func didSendHandshakeMessage(message : TLSHandshakeMessage) throws
    func didSendChangeCipherSpec() throws
    func didReceiveChangeCipherSpec() throws
    func didReceiveHandshakeMessage(message : TLSHandshakeMessage) throws
    func shouldContinueHandshakeWithMessage(message : TLSHandshakeMessage) -> Bool
    func didReceiveAlert(alert : TLSAlertMessage)
}

extension TLSContextStateMachine
{
    func didSendMessage(message : TLSMessage) throws {}
    func didSendHandshakeMessage(message : TLSHandshakeMessage) throws {}
    func didSendChangeCipherSpec() throws {}
    func didReceiveChangeCipherSpec() throws {}
    func didReceiveHandshakeMessage(message : TLSHandshakeMessage) throws {}
    func shouldContinueHandshakeWithMessage(message : TLSHandshakeMessage) -> Bool
    {
        return true
    }
    func didReceiveAlert(alert : TLSAlertMessage) {}
}

public class TLSContext
{
    public var protocolVersion : TLSProtocolVersion
    var negotiatedProtocolVersion : TLSProtocolVersion! = nil {
        didSet {
            self.recordLayer.protocolVersion = negotiatedProtocolVersion
        }
    }
    public var cipherSuites : [CipherSuite]?
    
    var cipherSuite : CipherSuite?
    
    var stateMachine : TLSContextStateMachine!
    
    var serverKey : CryptoKey?
    var clientKey : CryptoKey?
    
    var identity : Identity?
    
    var serverCertificates : [Certificate]?
    var clientCertificates : [Certificate]?
    
    var preMasterSecret     : [UInt8]? = nil {
        didSet {
            print("pre master secret = \(hex(preMasterSecret!))")
        }
    }

    var securityParameters  : TLSSecurityParameters
    
    var handshakeMessages : [TLSHandshakeMessage]
    
    let isClient : Bool
    
    var recordLayer : TLSRecordLayer!
    
    var dhKeyExchange : DHKeyExchange?
    var ecdhKeyExchange : ECDHKeyExchange?
    
    private var connectionEstablishedCompletionBlock : ((error : TLSError?) -> ())?
    
    init(protocolVersion: TLSProtocolVersion, dataProvider : TLSDataProvider, isClient : Bool = true)
    {
        self.protocolVersion = protocolVersion
        self.isClient = isClient
        self.handshakeMessages = []
        self.securityParameters = TLSSecurityParameters()
        self.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
        self.recordLayer = TLSRecordLayer(context: self, dataProvider: dataProvider)
        self.stateMachine = TLSStateMachine(context: self)
    }
    
    func copy(var isClient isClient: Bool? = nil) -> TLSContext
    {
        if isClient == nil {
            isClient = self.isClient
        }
        let context = TLSContext(protocolVersion: self.protocolVersion, dataProvider: self.recordLayer.dataProvider!, isClient: isClient!)
        
        context.cipherSuites = self.cipherSuites
        context.cipherSuite = self.cipherSuite
        
        context.serverKey = self.serverKey
        context.clientKey = self.clientKey
        context.identity = self.identity
        
        context.serverCertificates = self.serverCertificates
        context.clientCertificates = self.clientCertificates
        
        if let preMasterSecret = self.preMasterSecret {
            context.preMasterSecret = preMasterSecret
        }
        
        context.securityParameters = self.securityParameters
        context.handshakeMessages = self.handshakeMessages

        return context
    }
    
    func startConnection() throws
    {
        try self.sendClientHello()
        try self.receiveNextTLSMessage()
    }
    
    func acceptConnection() throws
    {
        try self.receiveNextTLSMessage()
    }
    
    func sendApplicationData(data : [UInt8]) throws
    {
        try self.recordLayer.sendData(contentType: .ApplicationData, data: data)
    }
    
    func sendMessage(message : TLSMessage) throws
    {
        try self.recordLayer.sendMessage(message)
        
        switch message.contentType
        {
        case .Handshake:
            break

        default:
            try self.stateMachine!.didSendMessage(message)
        }
    }
    
    func sendAlert(alert : TLSAlert, alertLevel : TLSAlertLevel) throws
    {
        let alertMessage = TLSAlertMessage(alert: alert, alertLevel: alertLevel)
        try self.sendMessage(alertMessage)
    }
    
    private func sendHandshakeMessage(message : TLSHandshakeMessage) throws
    {
        try self.sendMessage(message)
        self.handshakeMessages.append(message)
        try self.stateMachine!.didSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(message : TLSHandshakeMessage)
    {
        if let clientHello = message as? TLSClientHello {
            print("TLS version: \(clientHello.clientVersion)")
            print("Supported Cipher Suites:")
            for cipherSuite in clientHello.cipherSuites {
                print("\(cipherSuite)")
            }
        }
    }
    
    func _didReceiveMessage(message : TLSMessage) throws
    {
//        print((self.isClient ? "Client" : "Server" ) + ": did receive message \(TLSMessageNameForType(message.type))")

        switch (message.type)
        {
        case .ChangeCipherSpec:
            self.recordLayer.activateReadEncryptionParameters()
            try self.stateMachine!.didReceiveChangeCipherSpec()
            try self.receiveNextTLSMessage()
            
            break
            
        case .Handshake:
            let handshakeMessage = message as! TLSHandshakeMessage
            if self.stateMachine.shouldContinueHandshakeWithMessage(handshakeMessage) {
                try self._didReceiveHandshakeMessage(handshakeMessage)
            }

        case .Alert:
            let alert = message as! TLSAlertMessage
            self.stateMachine.didReceiveAlert(alert)

            break
            
        case .ApplicationData:
            break
        }
    }

    func _didReceiveHandshakeMessage(message : TLSHandshakeMessage) throws
    {
        let handshakeType = message.handshakeType

        if (handshakeType != .Finished) {
            // don't add the incoming Finished message to handshakeMessages.
            // We need to verify it's data against the handshake messages before it.
            self.handshakeMessages.append(message)
        }
        
        switch (handshakeType)
        {
        case .ClientHello:
            let clientHello = (message as! TLSClientHello)
            if clientHello.clientVersion < self.protocolVersion {
                self.negotiatedProtocolVersion = clientHello.clientVersion
            }
            self.securityParameters.clientRandom = DataBuffer(clientHello.random).buffer
            
            self.cipherSuite = self.selectCipherSuite(clientHello.cipherSuites)
            
            if self.cipherSuite == nil {
                try self.sendAlert(.HandshakeFailure, alertLevel: .Fatal)
            }
            
        case .ServerHello:
            let serverHello = message as! TLSServerHello
            let version = serverHello.version
            print("Server wants to speak \(version)")
            
            self.recordLayer.protocolVersion = version
            self.negotiatedProtocolVersion = version
            
            self.cipherSuite = serverHello.cipherSuite
            self.securityParameters.serverRandom = DataBuffer(serverHello.random).buffer
            if !serverHello.cipherSuite.needsServerKeyExchange()
            {
                self.preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: self.protocolVersion)).buffer
                self.setPendingSecurityParametersForCipherSuite(serverHello.cipherSuite)
                self.recordLayer.pendingSecurityParameters = self.securityParameters
            }
            
        case .Certificate:
            let certificateMessage = message as! TLSCertificateMessage
            self.serverCertificates = certificateMessage.certificates
            self.serverKey = certificateMessage.publicKey
            
        case .ServerKeyExchange:
            let keyExchangeMessage = message as! TLSServerKeyExchange
            
            if let diffieHellmanParameters = keyExchangeMessage.diffieHellmanParameters {
                let p = diffieHellmanParameters.p
                let g = diffieHellmanParameters.g
                let Ys = diffieHellmanParameters.Ys
                
                let dhKeyExchange = DHKeyExchange(primeModulus: p, generator: g)
                dhKeyExchange.peerPublicValue = Ys
                self.dhKeyExchange = dhKeyExchange
            }
            else if let ecDiffieHellmanParameters = keyExchangeMessage.ecDiffieHellmanParameters {
                print(ecDiffieHellmanParameters)
            }
            
            
        case .ServerHelloDone:
            break
            
        case .ClientKeyExchange:
            let clientKeyExchange = message as! TLSClientKeyExchange
            if let dhKeyExchange = self.dhKeyExchange {
                // Diffie-Hellman
                if let diffieHellmanPublicValue = clientKeyExchange.diffieHellmanPublicValue {
                    let secret = BigInt.random(dhKeyExchange.primeModulus)
                    dhKeyExchange.peerPublicValue = BigInt(diffieHellmanPublicValue.reverse())
                    self.preMasterSecret = (dhKeyExchange.calculateSharedSecret(secret)!.toArray() as [UInt8]).reverse()
                }
                else {
                    fatalError("Client Key Exchange has no encrypted master secret")
                }
            }
            else {
                // RSA
                if let encryptedPreMasterSecret = clientKeyExchange.encryptedPreMasterSecret {
                    self.preMasterSecret = self.identity!.privateKey.decrypt(encryptedPreMasterSecret)
                }
                else {
                    fatalError("Client Key Exchange has no encrypted master secret")
                }
            }
            
            
            self.setPendingSecurityParametersForCipherSuite(self.cipherSuite!)
            self.recordLayer.pendingSecurityParameters = self.securityParameters
            
        case .Finished:
            if (self.verifyFinishedMessage(message as! TLSFinished, isClient: !self.isClient)) {
                print((self.isClient ? "Client" : "Server" ) + ": Finished verified.")
                
                if !self.isClient {
                    self.handshakeMessages.append(message)
                }
            }
            else {
                print("Error: could not verify Finished message.")
                try sendAlert(.DecryptionFailed, alertLevel: .Fatal)
            }
            
        default:
            throw TLSError.Error("Unsupported handshake \(handshakeType.rawValue)")
        }

        try self.stateMachine!.didReceiveHandshakeMessage(message)
        
        if handshakeType != .Finished {
            try self.receiveNextTLSMessage()
        }
    }
    
    func sendClientHello() throws
    {
        let clientHelloRandom = Random()
        let clientHello = TLSClientHello(
            clientVersion: self.protocolVersion,
            random: clientHelloRandom,
            sessionID: nil,
            cipherSuites: self.cipherSuites!,
//            cipherSuites: [.TLS_RSA_WITH_NULL_SHA],
            compressionMethods: [.NULL])
        
        if self.cipherSuites!.contains({ if let descriptor = TLSCipherSuiteDescriptorForCipherSuite($0) { return descriptor.keyExchangeAlgorithm == .ECDHE_RSA} else { return false } }) {
            clientHello.extensions.append(TLSEllipticCurvesExtension(ellipticCurves: [.secp256r1, .secp384r1, .secp521r1]))
            clientHello.extensions.append(TLSEllipticCurvePointFormatsExtension(ellipticCurvePointFormats: [.uncompressed]))
        }
        
        self.securityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
        try self.sendHandshakeMessage(clientHello)
    }
    
    func sendServerHello() throws
    {
        let serverHelloRandom = Random()
        let serverHello = TLSServerHello(
            serverVersion: self.negotiatedProtocolVersion,
            random: serverHelloRandom,
            sessionID: nil,
            cipherSuite: self.cipherSuite!,
            compressionMethod: .NULL)
        
        self.securityParameters.serverRandom = DataBuffer(serverHelloRandom).buffer
        try self.sendHandshakeMessage(serverHello)
    }
    
    func sendCertificate() throws
    {
        let certificate = self.identity!.certificate
        let certificateMessage = TLSCertificateMessage(certificates: [certificate])
        
        try self.sendHandshakeMessage(certificateMessage);
    }
    
    func sendServerHelloDone() throws
    {
        try self.sendHandshakeMessage(TLSServerHelloDone())
    }
    
    func sendClientKeyExchange() throws
    {
        if let diffieHellmanKeyExchange = self.dhKeyExchange {
            // Diffie-Hellman
            let secret = BigInt.random(diffieHellmanKeyExchange.primeModulus)
            let publicValue = diffieHellmanKeyExchange.calculatePublicValue(secret)
            let sharedSecret = diffieHellmanKeyExchange.calculateSharedSecret(secret)!
            self.preMasterSecret = (sharedSecret.toArray() as [UInt8]).reverse()
            self.setPendingSecurityParametersForCipherSuite(self.cipherSuite!)
            self.recordLayer.pendingSecurityParameters = self.securityParameters

            let message = TLSClientKeyExchange(diffieHellmanPublicValue: (publicValue.toArray() as [UInt8]).reverse())
            try self.sendHandshakeMessage(message)
        }
        else {
            if let serverKey = self.serverKey {
                // RSA
                let message = TLSClientKeyExchange(preMasterSecret: self.preMasterSecret!, publicKey: serverKey)
                try self.sendHandshakeMessage(message)
            }
        }
    }

    func sendChangeCipherSpec() throws
    {
        let message = TLSChangeCipherSpec()
        try self.sendMessage(message)
        self.recordLayer.activateWriteEncryptionParameters()
        try self.stateMachine!.didSendChangeCipherSpec()
    }
    
    func sendFinished() throws
    {
        let verifyData = self.verifyDataForFinishedMessage(isClient: self.isClient)
        try self.sendHandshakeMessage(TLSFinished(verifyData: verifyData))
    }

    private func verifyFinishedMessage(finishedMessage : TLSFinished, isClient: Bool) -> Bool
    {
        let verifyData = self.verifyDataForFinishedMessage(isClient: isClient)

        return finishedMessage.verifyData == verifyData
    }

    private func verifyDataForFinishedMessage(isClient isClient: Bool) -> [UInt8]
    {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        
        var handshakeData = [UInt8]()
        for message in self.handshakeMessages {
            if let messageData = message.rawHandshakeMessageData {
                handshakeData.appendContentsOf(messageData)
            }
            else {
                var messageBuffer = DataBuffer()
                message.writeTo(&messageBuffer)
                
                handshakeData.appendContentsOf(messageBuffer.buffer)
            }
        }
        
        if self.negotiatedProtocolVersion < TLSProtocolVersion.TLS_v1_2 {
            let clientHandshakeMD5  = Hash_MD5(handshakeData)
            let clientHandshakeSHA1 = Hash_SHA1(handshakeData)
            
            let seed = clientHandshakeMD5 + clientHandshakeSHA1
            
            return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: seed, outputLength: 12)
        }
        else {
            let clientHandshake = Hash_SHA256(handshakeData)

            return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: clientHandshake, outputLength: 12)
        }
    }
    
    
    
    internal func PRF(secret secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
    {
        if self.negotiatedProtocolVersion < TLSProtocolVersion.TLS_v1_2 {
            /// PRF function as defined in RFC 2246, section 5, p. 12

            let halfSecretLength = secret.count / 2
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
            for i in 0 ..< output.count
            {
                output[i] = md5data[i] ^ sha1data[i]
            }
            
            return output
        }
        else {
            return P_hash(HMAC_SHA256, secret: secret, seed: label + seed, outputLength: outputLength)
        }
    }

    
    private func receiveNextTLSMessage() throws
    {
        let message = try self._readTLSMessage()

        try self._didReceiveMessage(message)
    }

    func readTLSMessage() throws -> TLSMessage
    {
        return try self._readTLSMessage()
    }
    
    private func _readTLSMessage() throws -> TLSMessage
    {
        return try self.recordLayer.readMessage()
    }
    
    private func setPendingSecurityParametersForCipherSuite(cipherSuite : CipherSuite)
    {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
        else {
            fatalError("Unkown cipher suite \(cipherSuite)")
        }
        let cipherAlgorithmDescriptor = cipherSuiteDescriptor.bulkCipherAlgorithm

        self.securityParameters.bulkCipherAlgorithm  = cipherAlgorithmDescriptor.algorithm
        self.securityParameters.encodeKeyLength      = cipherAlgorithmDescriptor.keySize
        self.securityParameters.blockLength          = cipherAlgorithmDescriptor.blockSize
        self.securityParameters.fixedIVLength        = cipherAlgorithmDescriptor.blockSize
        self.securityParameters.recordIVLength       = cipherAlgorithmDescriptor.blockSize
        self.securityParameters.hmacDescriptor       = cipherSuiteDescriptor.hmacDescriptor
        
        self.securityParameters.masterSecret = calculateMasterSecret()
    }
    
    // Calculate master secret as described in RFC 2246, section 8.1, p. 46
    private func calculateMasterSecret() -> [UInt8]
    {
        return PRF(secret: self.preMasterSecret!, label: [UInt8]("master secret".utf8), seed: self.securityParameters.clientRandom! + self.securityParameters.serverRandom!, outputLength: 48)
    }

    func selectCipherSuite(cipherSuites : [CipherSuite]) -> CipherSuite?
    {
        for clientCipherSuite in cipherSuites {
            for myCipherSuite in self.cipherSuites! {
                if clientCipherSuite == myCipherSuite {
                    return myCipherSuite
                }
            }
        }
        
        return nil
    }
}
