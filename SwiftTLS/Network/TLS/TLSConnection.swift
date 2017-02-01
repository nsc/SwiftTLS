//
//  TLSConnection.swift
//
//  Created by Nico Schmidt on 21.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import CommonCrypto

let tls1_3_prefix = [UInt8]("TLS 1.3, ".utf8)

public class TLSConnection
{
    public var configuration: TLSConfiguration
    public var context: TLSContext {
        return TLSClientContext()
    }
    
    var negotiatedProtocolVersion: TLSProtocolVersion? {
        didSet {
            if let version = negotiatedProtocolVersion {
                self.recordLayer.protocolVersion = version
            }
        }
    }
    
    var hostNames: [String]?
    
    var cipherSuite: CipherSuite?
    var stateMachine: TLSConnectionStateMachine?
    
    var serverKey: RSA?
    
    var serverCertificates: [X509.Certificate]?
    
    var preMasterSecret: [UInt8]? = nil
    
    var securityParameters: TLSSecurityParameters
    
    var handshakeMessages: [TLSHandshakeMessage]
    
    var isClient: Bool {
        return self is TLSClient
    }
    
    var recordLayer: TLSRecordLayer!
    
    var keyExchange: KeyExchange
    
    var signer: Signing?

    // The current session, if there is one already
    var currentSession: TLSSession?
    
    // The session ID that will be used once the handshake is finished and the session
    // can be set up
    var pendingSessionID: TLSSessionID?
    
    var isReusingSession: Bool
    
    var isInitialHandshake: Bool = true
    var isRenegotiatingSecurityParameters: Bool = false
    
    var hashAlgorithm: HashAlgorithm = .sha256
    
    typealias HashFunction = ([UInt8]) -> [UInt8]
    var hashFunction: HashFunction {
        switch self.hashAlgorithm {
        case .sha256:
            return Hash_SHA256

        case .sha384:
            return Hash_SHA384
            
        default:
            fatalError("Unsupported hash function \(self.hashAlgorithm)")
        }
    }
    
    var hmac: HMACFunction {
        switch self.hashAlgorithm {
        case .sha256:
            return HMAC_SHA256
            
        case .sha384:
            return HMAC_SHA384
            
        default:
            fatalError("Unsupported HMAC hash function \(self.hashAlgorithm)")
        }
    }
    
    private var connectionEstablishedCompletionBlock : ((_ error : TLSError?) -> ())?

    init(configuration: TLSConfiguration, dataProvider : TLSDataProvider? = nil)
    {
        self.configuration = configuration
        
        self.negotiatedProtocolVersion = configuration.supportedVersions.first!
        self.handshakeMessages = []
        self.securityParameters = TLSSecurityParameters()
        self.keyExchange = .rsa
        self.isReusingSession = false
        
        if let dataProvider = dataProvider {
            self.recordLayer = TLSRecordLayer(context: self, dataProvider: dataProvider)
        }
    }
    
    func reset() {
        self.currentSession = nil
        self.pendingSessionID = nil
        
        self.isInitialHandshake = true
        
        self.negotiatedProtocolVersion = configuration.supportedVersions.first!
        self.handshakeMessages = []
        self.securityParameters = TLSSecurityParameters()
        self.keyExchange = .rsa
        
        self.recordLayer = TLSRecordLayer(context: self, dataProvider: self.recordLayer.dataProvider!)
        self.stateMachine?.reset()
    }
    
    func didConnect() throws
    {
        try self.stateMachine?.didConnect()
    }

    func didRenegotiate()
    {
        print("Renegotiated security parameters successfully.")
    }

    
    func sendApplicationData(_ data : [UInt8]) throws
    {
        try self.recordLayer.sendData(contentType: .applicationData, data: data)
    }
    
    func sendMessage(_ message : TLSMessage) throws
    {
        try self.recordLayer.sendMessage(message)
        
        switch message.contentType
        {
        case .handshake:
            break

        default:
            try self.stateMachine?.didSendMessage(message)
        }
    }
    
    func sendAlert(_ alert : TLSAlert, alertLevel : TLSAlertLevel) throws
    {
        let alertMessage = TLSAlertMessage(alert: alert, alertLevel: alertLevel)
        try self.sendMessage(alertMessage)
    }
    
    func abortHandshake() throws
    {
        try self.sendAlert(.handshakeFailure, alertLevel: .fatal)
        throw TLSError.alert(alert: .handshakeFailure, alertLevel: .fatal)
    }
    
    func sendHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        try self.sendMessage(message)
        self.handshakeMessages.append(message)
        try self.stateMachine?.didSendHandshakeMessage(message)
    }
    
    func didReceiveHandshakeMessage(_ message : TLSHandshakeMessage)
    {
        if let clientHello = message as? TLSClientHello {
            print("TLS version: \(clientHello.legacyVersion)")
            print("Supported Cipher Suites:")
            for cipherSuite in clientHello.cipherSuites {
                print("\(cipherSuite)")
            }
        }
    }
    
    func _didReceiveMessage(_ message : TLSMessage) throws
    {
        switch (message.type)
        {
        case .changeCipherSpec:
            self.recordLayer.activateReadEncryptionParameters()
            try self.stateMachine?.didReceiveChangeCipherSpec()
            try self.receiveNextTLSMessage()
            
            break
            
        case .handshake:
            let handshakeMessage = message as! TLSHandshakeMessage
            if self.stateMachine == nil || self.stateMachine!.shouldContinueHandshake(with: handshakeMessage) {
                try self._didReceiveHandshakeMessage(handshakeMessage)
            }

        case .alert:
            let alert = message as! TLSAlertMessage
            self.stateMachine?.didReceiveAlert(alert)
            if alert.alertLevel == .fatal {
                throw TLSError.alert(alert: alert.alert, alertLevel: alert.alertLevel)
            }
            
            break
            
        case .applicationData:
            break
        }
    }

    func handleHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
    }
    

    func _didReceiveHandshakeMessage(_ message : TLSHandshakeMessage) throws
    {
        let handshakeType = message.handshakeType

        self.didReceiveHandshakeMessage(message)
        
        if (handshakeType != .finished) {
            // don't add the incoming Finished message to handshakeMessages.
            // We need to verify it's data against the handshake messages before it.
            self.handshakeMessages.append(message)
        }
        
        try self.handleHandshakeMessage(message)
        
        if handshakeType != .finished {
            try self.receiveNextTLSMessage()
        }
    }
        
    func saveVerifyDataForSecureRenegotiation(data: [UInt8], forClient isClient: Bool)
    {
        if self.securityParameters.isUsingSecureRenegotiation {
            if isClient {
                self.securityParameters.clientVerifyData = data
            }
            else {
                self.securityParameters.serverVerifyData = data
            }
        }
    }

    func verifyFinishedMessage(_ finishedMessage : TLSFinished, isClient: Bool, saveForSecureRenegotiation: Bool) -> Bool
    {
        guard finishedMessage.verifyData == self.verifyDataForFinishedMessage(isClient: isClient) else {
            return false
        }

        if saveForSecureRenegotiation {
            saveVerifyDataForSecureRenegotiation(data: finishedMessage.verifyData, forClient: isClient)
        }
        
        return true
    }

    func verifyDataForFinishedMessage(isClient: Bool) -> [UInt8]
    {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        
        var handshakeData = [UInt8]()
        for message in self.handshakeMessages {
            let handshakeMessageData : [UInt8]
            if let messageData = message.rawHandshakeMessageData {
                handshakeMessageData = messageData
            }
            else {
                var messageBuffer = DataBuffer()
                message.writeTo(&messageBuffer)
                
                handshakeMessageData = messageBuffer.buffer
            }

            handshakeData.append(contentsOf: handshakeMessageData)

        }
        
        if self.negotiatedProtocolVersion! < TLSProtocolVersion.v1_2 {
            let clientHandshakeMD5  = Hash_MD5(handshakeData)
            let clientHandshakeSHA1 = Hash_SHA1(handshakeData)
            
            let seed = clientHandshakeMD5 + clientHandshakeSHA1
            
            return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: seed, outputLength: 12)
        }
        else {
            let clientHandshake = self.hashFunction(handshakeData)

            assert(self.securityParameters.masterSecret != nil)
            
            return PRF(secret: self.securityParameters.masterSecret!, label: finishedLabel, seed: clientHandshake, outputLength: 12)
        }
    }
    
    internal func sign(_ data : [UInt8]) -> [UInt8]
    {
        guard let signer = self.signer else {
            fatalError("Unsupported signature algorithm \(self.configuration.signatureAlgorithm)")
        }
        
        return signer.sign(data: data, hashAlgorithm: self.configuration.hashAlgorithm)
    }
    
    internal func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
    {
        if self.negotiatedProtocolVersion! < TLSProtocolVersion.v1_2 {
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
            
            var output = [UInt8](repeating: 0, count: outputLength)
            for i in 0 ..< output.count
            {
                output[i] = md5data[i] ^ sha1data[i]
            }
            
            return output
        }
        else {
            return P_hash(self.hmac, secret: secret, seed: label + seed, outputLength: outputLength)
        }
    }

    // TLS 1.3 uses HKDF to derive its key material
    internal func HKDF_Extract(salt: [UInt8], inputKeyingMaterial: [UInt8]) -> [UInt8] {
        let HMAC = self.hmac
        return HMAC(salt, inputKeyingMaterial)
    }

    internal func HKDF_Expand(prk: [UInt8], info: [UInt8], outputLength: Int) -> [UInt8] {
        let HMAC = self.hmac
        
        let hashLength = self.hashAlgorithm.hashLength
        
        let n = Int(ceil(Double(outputLength)/Double(hashLength)))
        
        var output : [UInt8] = []
        var roundOutput : [UInt8] = []
        for i in 0..<n {
            roundOutput = HMAC(prk, roundOutput + info + [UInt8(i + 1)])
            output += roundOutput
        }
        
        return [UInt8](output[0..<hashLength])
    }
    
    internal func HKDF_Expand_Label(secret: [UInt8], label: [UInt8], hashValue: [UInt8], outputLength: Int) -> [UInt8] {
        
        let label = tls1_3_prefix + label
        var hkdfLabel = [UInt8((outputLength >> 8) & 0xff), UInt8(outputLength & 0xff)]
        hkdfLabel += [UInt8(label.count)] + label
        hkdfLabel += [UInt8(hashValue.count)] + hashValue
        
        return HKDF_Expand(prk: secret, info: hkdfLabel, outputLength: outputLength)
    }
    
    internal func Derive_Secret(secret: [UInt8], label: [UInt8], messages: [UInt8]) -> [UInt8] {
        let hashLength = self.hashAlgorithm.hashLength
        let hashValue = self.hashFunction(messages)
        
        return HKDF_Expand_Label(secret: secret, label: label, hashValue: hashValue, outputLength: hashLength)
    }
    
    func receiveNextTLSMessage() throws
    {
        let message = try self._readTLSMessage()

        try self._didReceiveMessage(message)
    }

    func readTLSMessage() throws -> TLSMessage
    {
        while true {
            let message = try self._readTLSMessage()
            
            if message.contentType == .applicationData {
                return message
            }
            
            try self._didReceiveMessage(message)
        }
    }
    
    private func _readTLSMessage() throws -> TLSMessage
    {
        return try self.recordLayer.readMessage()
    }
    
    func setPreMasterSecretAndCommitSecurityParameters(_ preMasterSecret : [UInt8], cipherSuite : CipherSuite? = nil)
    {
        var cipherSuite = cipherSuite
        if cipherSuite == nil {
            cipherSuite = self.cipherSuite
        }
        
        self.cipherSuite = cipherSuite
        self.preMasterSecret = preMasterSecret
        self.setPendingSecurityParametersForCipherSuite(cipherSuite!)
    }
    
    func setPendingSecurityParametersForCipherSuite(_ cipherSuite : CipherSuite)
    {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptorForCipherSuite(cipherSuite)
        else {
            fatalError("Unsupported cipher suite \(cipherSuite)")
        }
        let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm

        self.securityParameters.bulkCipherAlgorithm = cipherAlgorithm
        self.securityParameters.blockCipherMode     = cipherSuiteDescriptor.blockCipherMode
        self.securityParameters.cipherType          = cipherSuiteDescriptor.cipherType
        self.securityParameters.encodeKeyLength     = cipherAlgorithm.keySize
        self.securityParameters.blockLength         = cipherAlgorithm.blockSize
        self.securityParameters.fixedIVLength       = cipherSuiteDescriptor.fixedIVLength
        self.securityParameters.recordIVLength      = cipherSuiteDescriptor.recordIVLength
        self.securityParameters.hmac                = cipherSuiteDescriptor.hashFunction.macAlgorithm
        
        var useConfiguredHashFunctionForPRF = self.securityParameters.blockCipherMode! == .gcm || cipherSuiteDescriptor.keyExchangeAlgorithm == .ecdhe
        
        switch cipherSuiteDescriptor.hashFunction
        {
        case .sha256, .sha384:
            break
            
        default:
            useConfiguredHashFunctionForPRF = false
        }
        
        if !useConfiguredHashFunctionForPRF {
            // for non GCM or ECDHE cipher suites TLS 1.2 uses SHA256 for its PRF
            self.hashAlgorithm = .sha256
        }
        else {
            switch cipherSuiteDescriptor.hashFunction {
            case .sha256:
                self.hashAlgorithm = .sha256
                
            case .sha384:
                self.hashAlgorithm = .sha384
                
            default:
                print("Error: cipher suite \(cipherSuite) has \(cipherSuiteDescriptor.hashFunction)")
                fatalError("AEAD cipher suites can only use SHA256 or SHA384")
                break
            }
        }
        
        if let session = currentSession {
            self.securityParameters.masterSecret = session.masterSecret
        }
        else {
            self.securityParameters.masterSecret = calculateMasterSecret()
        }
        self.recordLayer.pendingSecurityParameters = self.securityParameters
    }
    
    // Calculate master secret as described in RFC 2246, section 8.1, p. 46
    private func calculateMasterSecret() -> [UInt8]
    {
        return PRF(secret: self.preMasterSecret!, label: [UInt8]("master secret".utf8), seed: self.securityParameters.clientRandom! + self.securityParameters.serverRandom!, outputLength: 48)
    }

    func selectCipherSuite(_ cipherSuites : [CipherSuite]) -> CipherSuite?
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
