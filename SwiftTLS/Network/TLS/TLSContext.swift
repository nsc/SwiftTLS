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
    
    init(data: [UInt8], context: TLSContext)
    {
        if context.negotiatedProtocolVersion == .TLS_v1_2 {
            self.hashAlgorithm = context.configuration.hashAlgorithm
            self.signatureAlgorithm = context.configuration.signatureAlgorithm
        }
        
        self.signature = context.sign(data)
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
    case Alert(alert : TLSAlert)
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
    public var configuration : TLSConfiguration
    
    var negotiatedProtocolVersion : TLSProtocolVersion {
        didSet {
            self.recordLayer.protocolVersion = negotiatedProtocolVersion
        }
    }
    
    var cipherSuite : CipherSuite?
    
    var stateMachine : TLSContextStateMachine!
    
    var serverKey : CryptoKey?
    var clientKey : CryptoKey?
    
    var serverCertificates : [Certificate]?
    var clientCertificates : [Certificate]?
    
    var preMasterSecret     : [UInt8]? = nil
    
    var securityParameters  : TLSSecurityParameters
    
    var handshakeMessages : [TLSHandshakeMessage]
    
    let isClient : Bool
    
    var recordLayer : TLSRecordLayer!
    
    var dhKeyExchange : DHKeyExchange?
    var ecdhKeyExchange : ECDHKeyExchange?
    
    var signer : Signing?
    
    private var connectionEstablishedCompletionBlock : ((error : TLSError?) -> ())?

    init(configuration: TLSConfiguration, dataProvider : TLSDataProvider, isClient : Bool = true)
    {
        self.configuration = configuration
        if !isClient {
            if let certificatePath = self.configuration.certificatePath {
                // we are currently only supporting RSA
                if let rsa = RSA.fromCertificateFile(certificatePath) {
                    self.signer = rsa
                }
            }
        }
        
        self.negotiatedProtocolVersion = configuration.protocolVersion
        self.isClient = isClient
        self.handshakeMessages = []
        self.securityParameters = TLSSecurityParameters()

        self.recordLayer = TLSRecordLayer(context: self, dataProvider: dataProvider)
        self.stateMachine = TLSStateMachine(context: self)
    }
    
    func copy(var isClient isClient: Bool? = nil) -> TLSContext
    {
        if isClient == nil {
            isClient = self.isClient
        }
        let context = TLSContext(configuration: self.configuration, dataProvider: self.recordLayer.dataProvider!, isClient: isClient!)
        
        context.configuration = self.configuration
        context.cipherSuite = self.cipherSuite
        
        context.serverKey = self.serverKey
        context.clientKey = self.clientKey
        
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
            if alert.alertLevel == .Fatal {
                throw TLSError.Alert(alert: alert.alert)
            }
            
            break
            
        case .ApplicationData:
            break
        }
    }

    func _didReceiveHandshakeMessage(message : TLSHandshakeMessage) throws
    {
        let handshakeType = message.handshakeType

        self.didReceiveHandshakeMessage(message)
        
        if (handshakeType != .Finished) {
            // don't add the incoming Finished message to handshakeMessages.
            // We need to verify it's data against the handshake messages before it.
            self.handshakeMessages.append(message)
        }
        
        switch (handshakeType)
        {
        case .ClientHello:
            let clientHello = (message as! TLSClientHello)
            if clientHello.clientVersion < self.configuration.protocolVersion {
                self.negotiatedProtocolVersion = clientHello.clientVersion
            }
            self.securityParameters.clientRandom = DataBuffer(clientHello.random).buffer
            
            self.cipherSuite = self.selectCipherSuite(clientHello.cipherSuites)
            
            if self.cipherSuite == nil {
                try self.sendAlert(.HandshakeFailure, alertLevel: .Fatal)
                throw TLSError.Error("No shared cipher suites. Client supports:" + clientHello.cipherSuites.map({"\($0)"}).reduce("", combine: {$0 + "\n" + $1}))
            }
            else {
                print("Selected cipher suite is \(self.cipherSuite!)")
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
                let preMasterSecret = DataBuffer(PreMasterSecret(clientVersion: self.configuration.protocolVersion)).buffer
                self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret, cipherSuite: serverHello.cipherSuite)
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
                dhKeyExchange.peerPublicKey = Ys

                self.dhKeyExchange = dhKeyExchange
            }
            else if let ecdhParameters = keyExchangeMessage.ecdhParameters {                
                if ecdhParameters.curveType != .NamedCurve {
                    throw TLSError.Error("Unsupported curve type \(ecdhParameters.curveType)")
                }
                
                guard
                    let namedCurve = ecdhParameters.namedCurve,
                    let curve = EllipticCurve.named(namedCurve)
                else {
                    throw TLSError.Error("Unsupported curve \(ecdhParameters.namedCurve)")
                }
                print("Using curve \(namedCurve)")
                
                self.ecdhKeyExchange = ECDHKeyExchange(curve: curve)
                self.ecdhKeyExchange!.peerPublicKey = ecdhParameters.publicKey
            }
            
            // verify signature
            if let certificate = self.serverCertificates?.first {
                if let rsa = certificate.publicKeySigner {
                    let signedData = keyExchangeMessage.signedParameters
                    var data = self.securityParameters.clientRandom!
                    data += self.securityParameters.serverRandom!
                    data += keyExchangeMessage.parametersData
                    
                    if !rsa.verify(signedData.signature, data: data) {
                        throw TLSError.Error("Signature error on server key exchange")
                    }
                }
            }
            
        case .ServerHelloDone:
            break
            
        case .ClientKeyExchange:
            let clientKeyExchange = message as! TLSClientKeyExchange
            var preMasterSecret : [UInt8]
            if let dhKeyExchange = self.dhKeyExchange {
                // Diffie-Hellman
                if let diffieHellmanPublicKey = clientKeyExchange.diffieHellmanPublicKey {
                    dhKeyExchange.peerPublicKey = diffieHellmanPublicKey
                    preMasterSecret = dhKeyExchange.calculateSharedSecret()!.asBigEndianData()
                }
                else {
                    fatalError("Client Key Exchange has no DH public key")
                }
            }
            else if let ecdhKeyExchange = self.ecdhKeyExchange {
                if let ecdhPublicKey = clientKeyExchange.ecdhPublicKey {
                    ecdhKeyExchange.peerPublicKey = ecdhPublicKey
                    preMasterSecret = ecdhKeyExchange.calculateSharedSecret()!.asBigEndianData()
                }
                else {
                    fatalError("Client Key Exchange has no ECDH public key")
                }
            }
            else {
                // RSA
                if let encryptedPreMasterSecret = clientKeyExchange.encryptedPreMasterSecret {
                    preMasterSecret = self.configuration.identity!.privateKey.decrypt(encryptedPreMasterSecret)!
                }
                else {
                    fatalError("Client Key Exchange has no encrypted master secret")
                }
            }
            
            self.setPreMasterSecretAndCommitSecurityParameters(preMasterSecret)
            
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
            clientVersion: self.configuration.protocolVersion,
            random: clientHelloRandom,
            sessionID: nil,
            cipherSuites: self.configuration.cipherSuites,
//            cipherSuites: [.TLS_RSA_WITH_NULL_SHA],
            compressionMethods: [.NULL])
        
        if self.configuration.cipherSuites.contains({ if let descriptor = TLSCipherSuiteDescriptorForCipherSuite($0) { return descriptor.keyExchangeAlgorithm == .ECDHE_RSA} else { return false } }) {
//            clientHello.extensions.append(TLSEllipticCurvesExtension(ellipticCurves: [.secp256r1, .secp384r1, .secp521r1]))
            clientHello.extensions.append(TLSEllipticCurvesExtension(ellipticCurves: [.secp521r1]))
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
        let certificate = self.configuration.identity!.certificate
        let certificateMessage = TLSCertificateMessage(certificates: [certificate])
        
        try self.sendHandshakeMessage(certificateMessage);
    }
    
    func sendServerHelloDone() throws
    {
        try self.sendHandshakeMessage(TLSServerHelloDone())
    }
    
    func sendServerKeyExchange() throws
    {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(self.cipherSuite!) else {
            throw TLSError.Error("No cipher suite")
        }
        
        switch cipherSuiteDescriptor.keyExchangeAlgorithm
        {
        case .DHE_RSA:
            guard var dhParameters = self.configuration.dhParameters else {
                throw TLSError.Error("No DH parameters set in configuration")
            }
            
            self.dhKeyExchange = DHKeyExchange(dhParameters: dhParameters)

            // use new public key for each key exchange
            dhParameters.Ys = self.dhKeyExchange!.calculatePublicKey()
            
            let message = TLSServerKeyExchange(dhParameters: dhParameters, context: self)
            try self.sendHandshakeMessage(message)
            
        case .ECDHE_RSA:
            guard var ecdhParameters = self.configuration.ecdhParameters else {
                throw TLSError.Error("No ECDH parameters set in configuration")
            }

            let ecdhKeyExchange = ECDHKeyExchange(curve: ecdhParameters.curve)
            let Q = ecdhKeyExchange.calculatePublicKey()
            self.ecdhKeyExchange = ecdhKeyExchange
            
            ecdhParameters.publicKey = Q
            let message = TLSServerKeyExchange(ecdhParameters: ecdhParameters, context:self)
            try self.sendHandshakeMessage(message)
            break
            
        default:
            throw TLSError.Error("Cipher suite \(self.cipherSuite) doesn't need server key exchange")
        }
    }

    func sendClientKeyExchange() throws
    {
        if let diffieHellmanKeyExchange = self.dhKeyExchange
        {
            // Diffie-Hellman
            let publicKey = diffieHellmanKeyExchange.calculatePublicKey()
            let sharedSecret = diffieHellmanKeyExchange.calculateSharedSecret()!

            self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret.asBigEndianData())
            
            let message = TLSClientKeyExchange(diffieHellmanPublicKey: publicKey)
            try self.sendHandshakeMessage(message)
        }
        else if let ecdhKeyExchange = self.ecdhKeyExchange
        {
            let Q = ecdhKeyExchange.calculatePublicKey()
            let sharedSecret = ecdhKeyExchange.calculateSharedSecret()!
            
            self.setPreMasterSecretAndCommitSecurityParameters(sharedSecret.asBigEndianData())
            
            let message = TLSClientKeyExchange(ecdhPublicKey: Q)
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

            assert(self.securityParameters.masterSecret != nil)
            
            return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: clientHandshake, outputLength: 12)
        }
    }
    
    internal func sign(data : [UInt8]) -> [UInt8]
    {
        guard let signer = self.signer else {
            fatalError("Unsupported signature algorithm \(self.configuration.signatureAlgorithm)")
        }
        
        return signer.sign(data, hashAlgorithm: self.configuration.hashAlgorithm)
    }
    
    internal func PRF(secret secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
    {
        if self.negotiatedProtocolVersion < TLSProtocolVersion.TLS_v1_2 {
            /// PRF function as defined in RFC 2246, section 5, p. 12

            let halfSecretLength = secret.count / 2
            let S1 : [UInt8]
            let S2 : [UInt8]
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
    
    private func setPreMasterSecretAndCommitSecurityParameters(preMasterSecret : [UInt8], cipherSuite : CipherSuite? = nil)
    {
        var cipherSuite = cipherSuite
        if cipherSuite == nil {
            cipherSuite = self.cipherSuite
        }
        self.preMasterSecret = preMasterSecret
        self.setPendingSecurityParametersForCipherSuite(cipherSuite!)
        self.recordLayer.pendingSecurityParameters = self.securityParameters
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
            for myCipherSuite in self.configuration.cipherSuites {
                if clientCipherSuite == myCipherSuite {
                    return myCipherSuite
                }
            }
        }
        
        return nil
    }
}
