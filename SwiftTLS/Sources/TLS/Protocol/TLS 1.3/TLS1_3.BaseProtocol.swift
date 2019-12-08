//
//  TLS1_3.BaseProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLS1_3 {}

extension TLS1_3 {
    static let tls1_3_prefix                        = [UInt8]("tls13 ".utf8)
    
    static let externalPSKBinderSecretLabel         = [UInt8]("ext binder".utf8)
    static let resumptionPSKBinderSecretLabel       = [UInt8]("res binder".utf8)
    static let clientEarlyTrafficSecretLabel        = [UInt8]("c e traffic".utf8)
    static let earlyExporterMasterSecretLabel       = [UInt8]("e exp master".utf8)

    static let clientHandshakeTrafficSecretLabel    = [UInt8]("c hs traffic".utf8)
    static let serverHandshakeTrafficSecretLabel    = [UInt8]("s hs traffic".utf8)
    static let clientApplicationTrafficSecretLabel  = [UInt8]("c ap traffic".utf8)
    static let serverApplicationTrafficSecretLabel  = [UInt8]("s ap traffic".utf8)
    static let exporterSecretLabel                  = [UInt8]("exp master".utf8)
    static let resumptionMasterSecretLabel          = [UInt8]("res master".utf8)
    static let finishedLabel                        = [UInt8]("finished".utf8)
    static let derivedLabel                         = [UInt8]("derived".utf8)
    static let resumptionLabel                      = [UInt8]("resumption".utf8)

    static let clientCertificateVerifyContext       = [UInt8]("TLS 1.3, client CertificateVerify".utf8)
    static let serverCertificateVerifyContext       = [UInt8]("TLS 1.3, server CertificateVerify".utf8)
    
    class HandshakeState {
        var preSharedKey: [UInt8]?
        var earlySecret: [UInt8]?
        var clientEarlyTrafficSecret: [UInt8]?
        var handshakeSecret: [UInt8]?
        var clientHandshakeTrafficSecret: [UInt8]?
        var serverHandshakeTrafficSecret: [UInt8]?
        var masterSecret: [UInt8]?
        var clientTrafficSecret: [UInt8]?
        var serverTrafficSecret: [UInt8]?
        var sessionResumptionSecret: [UInt8]?
        var resumptionBinderSecret: [UInt8]?
        var selectedIdentity: UInt16?
    }
    
    class BaseProtocol {
        internal weak var connection: TLSConnection!
        
        var recordLayer: RecordLayer! {
            return (self.connection.recordLayer as! RecordLayer)
        }
        
        var handshakeState: HandshakeState = HandshakeState()

        var isUsingPreSharedKey: Bool {
            return self.handshakeState.preSharedKey != nil
        }
        
        var context: TLSContext {
            return self.connection.context
        }
        
        init(connection: TLSConnection)
        {
            self.connection = connection
            
            reset()
        }
        
        func reset() {
        }
        
        func sendCertificate() throws
        {
            let certificates = self.connection.configuration.identity!.certificateChain
            let certificateMessage = TLSCertificateMessage(certificates: certificates)
            
            try self.connection.sendHandshakeMessage(certificateMessage);
        }
        
        func sendCertificateVerify() throws
        {
            let identity = self.connection.configuration.identity!
            var signer = identity.signer(with: self.connection.configuration.hashAlgorithm)
            
            var proofData = [UInt8](repeating: 0x20, count: 64)
            proofData += connection.isClient ? clientCertificateVerifyContext : serverCertificateVerifyContext
            proofData += [0]
            proofData += self.transcriptHash
            
            if signer is RSA {
                let hashAlgorithm: HashAlgorithm = .sha256
                signer.algorithm = .rsassa_pss(hash: hashAlgorithm, saltLength: hashAlgorithm.hashLength)
            }
            else if signer is ECDSA {
                let algorithm = signer.algorithm
                switch algorithm {
                case .ecPublicKey(let curveName, _):
                    signer.algorithm = .ecPublicKey(curveName: curveName, hash: .sha256)
                
                default:
                    fatalError("Unsupported signature algotihm \(algorithm)")
                }
            }
            
            let signature = try signer.sign(data: proofData)
            let certificateVerify = TLSCertificateVerify(algorithm: TLSSignatureScheme(signatureAlgorithm: signer.algorithm)!, signature: signature)
            
            try self.connection.sendHandshakeMessage(certificateVerify)
        }
        
        func handleCertificate(_ certificate: TLSCertificateMessage) {
            self.connection.peerCertificates = certificate.certificates
        }

        func handleCertificateVerify(_ certificateVerify: TLSCertificateVerify) throws {
            guard let certificate = self.connection.peerCertificates?.first,
                var signer = certificate.publicKeySigner,
                let signatureAlgorithm = certificateVerify.algorithm.signatureAlgorithm
            else {
                try self.connection.abortHandshake()
            }

            signer.algorithm = signatureAlgorithm
            
            let peerIsClient = !connection.isClient
            var proofData = [UInt8](repeating: 0x20, count: 64)
            proofData += peerIsClient ? clientCertificateVerifyContext : serverCertificateVerifyContext
            proofData += [0]
            proofData += self.transcriptHash

            let signature = certificateVerify.signature
            
            guard let verified = try? signer.verify(signature: signature, data: proofData),
                verified
            else {
                try self.connection.abortHandshake(with: .decryptError)
            }
            
            self.connection.handshakeMessages.append(certificateVerify)
        }

        func handleHandshakeMessage(_ handshakeMessage: TLSHandshakeMessage) throws -> Bool {
            switch handshakeMessage.handshakeType {
            case .certificateVerify:
                try self.handleCertificateVerify(handshakeMessage as! TLSCertificateVerify)
            
            default:
                return false
            }
            
            return true
        }
        
        func handleMessage(_ message: TLSMessage) throws {
            switch message.type
            {
            case .handshake(_):
                _ = try self.handleHandshakeMessage(message as! TLSHandshakeMessage)
                
            default:
                break
            }
        }

        var transcriptHash: [UInt8] {
            return connection.transcriptHash
        }
        
        func finishedData(forClient isClient: Bool) -> [UInt8] {
            let secret = isClient ? handshakeState.clientHandshakeTrafficSecret! : handshakeState.serverHandshakeTrafficSecret!

            let finishedKey = deriveFinishedKey(secret: secret)
            
            let transcriptHash = self.transcriptHash
            
            let finishedData = connection.hmac(finishedKey, transcriptHash)
            
            return finishedData
        }
        
        func sendFinished() throws
        {
            fatalError("sendFinished not overridden")
        }
        
        func binderValueWithHashAlgorithm(_ hashAlgorithm: HashAlgorithm, binderKey: [UInt8], transcriptHash: [UInt8]) -> [UInt8] {

            let binder = hashAlgorithm.macAlgorithm.hmacFunction(binderKey, transcriptHash)
            
            return binder
        }
        
        func ticketsForCurrentConnection(at currentTime: Date) -> [Ticket] {
            guard let serverNames = connection.serverNames, serverNames.count > 0 else {
                return []
            }
            
            return self.context.ticketStorage[serverName: serverNames.first!].filter({$0.isValid(at: currentTime)})
        }
        
        // TLS 1.3 uses HKDF to derive its key material
        internal func HKDF_Extract(salt: [UInt8], inputKeyingMaterial: [UInt8]) -> [UInt8] {
            let HMAC = connection.hmac
            return HMAC(salt, inputKeyingMaterial)
        }
        
        internal func HKDF_Expand(prk: [UInt8], info: [UInt8], outputLength: Int) -> [UInt8] {
            let HMAC = connection.hmac
            
            let hashLength = connection.hashAlgorithm.hashLength
            
            let n = Int(ceil(Double(outputLength)/Double(hashLength)))
            
            var output : [UInt8] = []
            var roundOutput : [UInt8] = []
            for i in 0..<n {
                roundOutput = HMAC(prk, roundOutput + info + [UInt8(i + 1)])
                output += roundOutput
            }
            
            return [UInt8](output[0..<outputLength])
        }
        
        func HKDF_Expand_Label(secret: [UInt8], label: [UInt8], hashValue: [UInt8], outputLength: Int) -> [UInt8] {
            
            let label = tls1_3_prefix + label
            var hkdfLabel = [UInt8((outputLength >> 8) & 0xff), UInt8(outputLength & 0xff)]
            hkdfLabel += [UInt8(label.count)] + label
            hkdfLabel += [UInt8(hashValue.count)] + hashValue
            
            return HKDF_Expand(prk: secret, info: hkdfLabel, outputLength: outputLength)
        }
        
        func Derive_Secret(secret: [UInt8], label: [UInt8], transcriptHash: [UInt8]) -> [UInt8] {
            return HKDF_Expand_Label(secret: secret, label: label, hashValue: transcriptHash, outputLength: transcriptHash.count)
        }

        func deriveEarlySecret() {
            let zeroes = [UInt8](repeating: 0, count: connection.hashAlgorithm.hashLength)
            self.handshakeState.earlySecret = HKDF_Extract(salt: zeroes, inputKeyingMaterial: self.handshakeState.preSharedKey ?? zeroes)
        }
        
        func deriveEarlyTrafficSecret() {
            let clientEarlyTrafficSecret = Derive_Secret(secret: self.handshakeState.earlySecret!, label: TLS1_3.clientEarlyTrafficSecretLabel, transcriptHash: connection.transcriptHash)
            self.handshakeState.clientEarlyTrafficSecret = clientEarlyTrafficSecret
        }
        
        func activateEarlyTrafficSecret() {
            if self.connection.isClient {
                log("Client: activate early traffic secret")
                self.recordLayer.changeWriteKeys(withTrafficSecret: self.handshakeState.clientEarlyTrafficSecret!)
                
//                log("Client: key = \(self.recordLayer.writeEncryptionParameters!.key)")
            }
            else {
                log("Server: activate early traffic secret")
                self.recordLayer.changeReadKeys(withTrafficSecret: self.handshakeState.clientEarlyTrafficSecret!)

//                log("Server: key = \(self.recordLayer.readEncryptionParameters!.key)")
            }
        }
        
        internal func deriveResumptionPSKBinderSecret() -> [UInt8] {
            guard let earlySecret = self.handshakeState.earlySecret else {
                fatalError("Early Secret must be derived before resumption binder secret")
            }
            
            return Derive_Secret(secret: earlySecret, label: resumptionPSKBinderSecretLabel, transcriptHash: self.connection.hashAlgorithm.hashFunction([]))
        }
                
        internal func deriveHandshakeSecret(with keyExchange: PFSKeyExchange) {
            let sharedSecret = keyExchange.calculateSharedSecret()

            let derivedSecret = Derive_Secret(secret: self.handshakeState.earlySecret!, label: derivedLabel, transcriptHash: self.connection.hashAlgorithm.hashFunction([]))
            let handshakeSecret = HKDF_Extract(salt: derivedSecret, inputKeyingMaterial: sharedSecret!)
            self.handshakeState.handshakeSecret = handshakeSecret
            
            let transcriptHash = connection.transcriptHash
            
            let clientHandshakeSecret = Derive_Secret(secret: handshakeSecret, label: TLS1_3.clientHandshakeTrafficSecretLabel, transcriptHash: transcriptHash)
            let serverHandshakeSecret = Derive_Secret(secret: handshakeSecret, label: TLS1_3.serverHandshakeTrafficSecretLabel, transcriptHash: transcriptHash)
            
            self.handshakeState.clientHandshakeTrafficSecret = clientHandshakeSecret
            self.handshakeState.serverHandshakeTrafficSecret = serverHandshakeSecret
        }
        
        internal func deriveApplicationTrafficSecrets() {
            let zeroes = [UInt8](repeating: 0, count: connection.hashAlgorithm.hashLength)
            
            let derivedSecret = Derive_Secret(secret: self.handshakeState.handshakeSecret!, label: derivedLabel, transcriptHash: self.connection.hashAlgorithm.hashFunction([]))

            let masterSecret = HKDF_Extract(salt: derivedSecret, inputKeyingMaterial: zeroes)
            self.handshakeState.masterSecret = masterSecret
            
            let transcriptHash = connection.transcriptHash

            let clientTrafficSecret = Derive_Secret(secret: masterSecret, label: TLS1_3.clientApplicationTrafficSecretLabel, transcriptHash: transcriptHash)
            let serverTrafficSecret = Derive_Secret(secret: masterSecret, label: TLS1_3.serverApplicationTrafficSecretLabel, transcriptHash: transcriptHash)

            self.handshakeState.clientTrafficSecret = clientTrafficSecret
            self.handshakeState.serverTrafficSecret = serverTrafficSecret
        }
        
        internal func deriveSessionResumptionSecret() {
            guard let masterSecret = self.handshakeState.masterSecret else {
                fatalError("deriveSessionResumptionSecret called before master secret has been derived.")
            }
            
            let transcriptHash = connection.transcriptHash
            let sessionResumptionSecret = Derive_Secret(secret: masterSecret,
                                                        label: TLS1_3.resumptionMasterSecretLabel,
                                                        transcriptHash: transcriptHash)

            self.handshakeState.sessionResumptionSecret = sessionResumptionSecret
        }
        
        internal func deriveFinishedKey(secret: [UInt8]) -> [UInt8] {
            let hashLength = connection.hashAlgorithm.hashLength
            let finishedKey = HKDF_Expand_Label(secret: secret, label: finishedLabel, hashValue: [], outputLength: hashLength)
            
            return finishedKey
        }
        
        internal func deriveBinderKey() -> [UInt8] {
            guard let resumptionBinderSecret = self.handshakeState.resumptionBinderSecret else {
                fatalError("resumption binder secret used before it was derived")
            }

            let binderKey = deriveFinishedKey(secret: resumptionBinderSecret)
            
            return binderKey
        }
    }
}
