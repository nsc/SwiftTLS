//
//  TLS1_3.BaseProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

struct TLS1_3 {}

extension TLS1_3 {
    static let clientHandshakeTrafficSecretLabel    = [UInt8]("c hs traffic".utf8)
    static let serverHandshakeTrafficSecretLabel    = [UInt8]("s hs traffic".utf8)
    static let clientApplicationTrafficSecretLabel  = [UInt8]("c ap traffic".utf8)
    static let serverApplicationTrafficSecretLabel  = [UInt8]("s ap traffic".utf8)
    static let exporterSecretLabel                  = [UInt8]("exp master".utf8)
    static let resumptionMasterSecretLabel          = [UInt8]("res master".utf8)
    static let finishedLabel                        = [UInt8]("finished".utf8)
    static let derivedLabel                         = [UInt8]("derived".utf8)

    static let clientCertificateVerifyContext       = [UInt8]("TLS 1.3, client CertificateVerify".utf8)
    static let serverCertificateVerifyContext       = [UInt8]("TLS 1.3, server CertificateVerify".utf8)
    
    class HandshakeState {
        var earlySecret: [UInt8]?
        var handshakeSecret: [UInt8]?
        var clientHandshakeTrafficSecret: [UInt8]?
        var serverHandshakeTrafficSecret: [UInt8]?
        var masterSecret: [UInt8]?
        var clientTrafficSecret: [UInt8]?
        var serverTrafficSecret: [UInt8]?
    }
    
    class BaseProtocol {
        internal weak var connection: TLSConnection!
        
        var recordLayer: RecordLayer! {
            return self.connection.recordLayer as! RecordLayer
        }
        
        var handshakeState: HandshakeState = HandshakeState()
        var peerHandshakeState: HandshakeState = HandshakeState()
        
        init(connection: TLSConnection)
        {
            self.connection = connection
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
            let signer = identity.signer
            
            var proofData = [UInt8](repeating: 0x20, count: 64)
            proofData += connection.isClient ? clientCertificateVerifyContext : serverCertificateVerifyContext
            proofData += [0]
            proofData += self.handshakeHash
            
            let signature = try signer.sign(data: proofData)
            let certificateVerify = TLSCertificateVerify(algorithm: signer.signatureScheme, signature: signature)
            
            try self.connection.sendHandshakeMessage(certificateVerify)
        }
        
        var handshakeHash: [UInt8] {
            let handshakeData = connection.handshakeMessageData
            return connection.hashAlgorithm.hashFunction(handshakeData)
        }
        
        func finishedData(forClient isClient: Bool) -> [UInt8]
        {
            let secret = isClient ? handshakeState.clientHandshakeTrafficSecret! : handshakeState.serverHandshakeTrafficSecret!
            let hashLength = connection.hashAlgorithm.hashLength
            let finishedKey = HKDF_Expand_Label(secret: secret, label: finishedLabel, hashValue: [], outputLength: hashLength)

            let handshakeHash = self.handshakeHash
            
            let finishedData = connection.hmac(finishedKey, handshakeHash)
            
            return finishedData
        }
        
        func sendFinished() throws
        {
            fatalError("sendFinished not overridden")
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
        
        internal func HKDF_Expand_Label(secret: [UInt8], label: [UInt8], hashValue: [UInt8], outputLength: Int) -> [UInt8] {
            
            let label = tls1_3_prefix + label
            var hkdfLabel = [UInt8((outputLength >> 8) & 0xff), UInt8(outputLength & 0xff)]
            hkdfLabel += [UInt8(label.count)] + label
            hkdfLabel += [UInt8(hashValue.count)] + hashValue
            
            return HKDF_Expand(prk: secret, info: hkdfLabel, outputLength: outputLength)
        }
        
        internal func Derive_Secret(secret: [UInt8], label: [UInt8], messages: [UInt8]) -> [UInt8] {
            let hashLength = connection.hashAlgorithm.hashLength
            let hashValue = connection.hashAlgorithm.hashFunction(messages)
            
            return HKDF_Expand_Label(secret: secret, label: label, hashValue: hashValue, outputLength: hashLength)
        }

        internal func deriveEarlySecret() {
            let zeroes = [UInt8](repeating: 0, count: connection.hashAlgorithm.hashLength)
            self.handshakeState.earlySecret = HKDF_Extract(salt: zeroes, inputKeyingMaterial: connection.preSharedKey ?? zeroes)
            
            print("early secret: \(hex(self.handshakeState.earlySecret!))")
        }
        
        internal func deriveHandshakeSecret(with keyExchange: PFSKeyExchange) {
            let sharedSecret = keyExchange.calculateSharedSecret()

            let derivedSecret = Derive_Secret(secret: self.handshakeState.earlySecret!, label: derivedLabel, messages: [])
            let handshakeSecret = HKDF_Extract(salt: derivedSecret, inputKeyingMaterial: sharedSecret!)
            self.handshakeState.handshakeSecret = handshakeSecret
            
            let handshakeMessages = connection.handshakeMessageData
            
            let clientHandshakeSecret = Derive_Secret(secret: handshakeSecret, label: TLS1_3.clientHandshakeTrafficSecretLabel, messages: handshakeMessages)
            let serverHandshakeSecret = Derive_Secret(secret: handshakeSecret, label: TLS1_3.serverHandshakeTrafficSecretLabel, messages: handshakeMessages)
            
            print("clientHandshakeSecret: \(hex(clientHandshakeSecret))")
            print("serverHandshakeSecret: \(hex(serverHandshakeSecret))")

            self.handshakeState.clientHandshakeTrafficSecret = clientHandshakeSecret
            self.handshakeState.serverHandshakeTrafficSecret = serverHandshakeSecret

            self.recordLayer.changeTrafficSecrets(clientTrafficSecret: clientHandshakeSecret, serverTrafficSecret: serverHandshakeSecret)
        }
        
        internal func deriveApplicationTrafficSecrets() {
            let zeroes = [UInt8](repeating: 0, count: connection.hashAlgorithm.hashLength)
            
            let derivedSecret = Derive_Secret(secret: self.handshakeState.handshakeSecret!, label: derivedLabel, messages: [])

            let masterSecret = HKDF_Extract(salt: derivedSecret, inputKeyingMaterial: zeroes)
            self.handshakeState.masterSecret = masterSecret
            
            let handshakeMessages = connection.handshakeMessageData

            let clientTrafficSecret = Derive_Secret(secret: masterSecret, label: TLS1_3.clientApplicationTrafficSecretLabel, messages: handshakeMessages)
            let serverTrafficSecret = Derive_Secret(secret: masterSecret, label: TLS1_3.serverApplicationTrafficSecretLabel, messages: handshakeMessages)
            
            print("clientTrafficSecret: \(hex(clientTrafficSecret))")
            print("serverTrafficSecret: \(hex(serverTrafficSecret))")

            self.handshakeState.clientTrafficSecret = clientTrafficSecret
            self.handshakeState.serverTrafficSecret = serverTrafficSecret
        }

    }
}
