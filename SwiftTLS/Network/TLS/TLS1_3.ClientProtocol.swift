//
//  TLS1_3.ClientProtocol.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.01.17.
//  Copyright © 2017 Nico Schmidt. All rights reserved.
//

import Foundation

extension TLS1_3 {
    class ClientProtocol : BaseProtocol, TLSClientProtocol {
        weak var client: TLSClient! {
            return self.connection as! TLSClient
        }
        
        init(client: TLSClient)
        {
            super.init(connection: client)
        }
        
        func sendClientHello() throws
        {
            let cipherSuites = client.configuration.cipherSuites
            let clientHelloRandom = Random()
            let clientHello = TLSClientHello(
                configuration: client.configuration,
                random: clientHelloRandom,
                sessionID: client.pendingSessionID,
                cipherSuites: cipherSuites,
                compressionMethods: [.null])
            
            if client.hostNames != nil {
                clientHello.extensions.append(TLSServerNameExtension(serverNames: client.hostNames!))
            }
            
            guard let groups = client.configuration.supportedGroups else {
                throw TLSError.error("TLS 1.3 configuration is missing supported key shares.")
            }
            
            clientHello.extensions.append(TLSSupportedGroupsExtension(ellipticCurves: groups))
            
            var keyShareEntries : [KeyShareEntry] = []
            for group in groups {
                
                if let curve = EllipticCurve.named(group) {
                    let keyExchange = ECDHKeyExchange(curve: curve)
                    let Q = keyExchange.calculatePublicKey()
                    
                    let data = DataBuffer(Q).buffer
                    keyShareEntries.append(KeyShareEntry(namedGroup: group, keyExchange: data))
                }
            }
            
            clientHello.extensions.append(TLSSignatureAlgorithmExtension(signatureAlgorithms: [.rsa_pkcs1_sha256, .rsa_pss_sha256]))
            clientHello.extensions.append(TLSKeyShareExtension(keyShare: .clientHello(clientShares: keyShareEntries)))
                
            client.securityParameters.clientRandom = DataBuffer(clientHelloRandom).buffer
            
            try client.sendHandshakeMessage(clientHello)
        }
        
        func handleServerHello(_ serverHello: TLSServerHello) throws {
            guard serverHello.version == .v1_3 else {
        
                // If the server does not support TLS 1.3, fall back to lower version
                // if the configuration supports it
        
                if !client.configuration.supports(serverHello.version) {
                    try client.abortHandshake()
                    return
                }
                
                switch serverHello.version {
                case TLSProtocolVersion.v1_2:
                    client.protocolHandler = TLS1_2.ClientProtocol(client: client)
                    try client.protocolHandler.handleServerHello(serverHello)
                    
                default:
                    try client.abortHandshake()
                }
                
                return
            }
            
        }
        
        func handleMessage(_ message: TLSMessage) throws {
            
        }
        
        func handleCertificate(_ certificate: TLSCertificateMessage) {
            
        }
        
        func handleFinished(_ finished: TLSFinished) throws {
        }
        
    }
}
