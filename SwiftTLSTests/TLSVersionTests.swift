//
//  TLSVersionTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 14.10.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import XCTest

@testable import SwiftTLS

class TLSVersionTests: XCTestCase {

    struct Alert: Error {}
    class Server : TLSServer
    {
        private var _negotiatedProtocolVersion: TLSProtocolVersion? = nil
        override var negotiatedProtocolVersion : TLSProtocolVersion? {
            get {
                return _negotiatedProtocolVersion
            }
            set {
                _negotiatedProtocolVersion = newValue
            }
        }
        override func sendHandshakeMessage(_ message: TLSHandshakeMessage) throws {
        }
        
        var hasAbortedHandshake: Bool = false
        override func abortHandshake() throws {
            hasAbortedHandshake = true
            throw Alert()
        }
    }

    class Client : TLSClient
    {
        private var _negotiatedProtocolVersion: TLSProtocolVersion? = nil
        override var negotiatedProtocolVersion : TLSProtocolVersion? {
            get {
                return _negotiatedProtocolVersion
            }
            set {
                _negotiatedProtocolVersion = newValue
            }
        }
        override func sendHandshakeMessage(_ message: TLSHandshakeMessage) throws {
        }
        
        var hasAbortedHandshake: Bool = false
        override func abortHandshake() throws {
            hasAbortedHandshake = true
            throw Alert()
        }
    }

    func receiveClientHello(with version: TLSProtocolVersion, highestSupportedVersion: TLSProtocolVersion, result: (Server) -> ())
    {
        let clientHello = TLSClientHello(configuration: TLSConfiguration(supportedVersions: [version]),
                                         random: Random(),
                                         sessionID: nil,
                                         cipherSuites: [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256])
        
        
        let server = Server(configuration: TLSConfiguration(supportedVersions: [highestSupportedVersion]))
        
        
        
        do {
            try server.handleHandshakeMessage(clientHello)
        } catch _ {
        }
        
        
        result(server)
    }
    
    func test_receiveClientHello_withHigherUnknownVersion_fallsBackToHighestSupportedVersion() {
        let version = TLSProtocolVersion(major: 10, minor: 10)
        let highestSupportedVersion = TLSProtocolVersion.v1_2

        receiveClientHello(with: version, highestSupportedVersion: highestSupportedVersion, result: { (server: Server) in
            XCTAssert(server.negotiatedProtocolVersion == highestSupportedVersion)
        })
    }

    func test_receiveClientHello_withLowerUnknownVersion_abortsHandshake() {
        let version = TLSProtocolVersion(major: 1, minor: 1)
        let highestSupportedVersion = TLSProtocolVersion.v1_1
        
        receiveClientHello(with: version, highestSupportedVersion: highestSupportedVersion, result: { (server: Server) in
            XCTAssert(server.hasAbortedHandshake)
        })
    }
    
    func receiveServerHello(with version: TLSProtocolVersion, highestSupportedVersion: TLSProtocolVersion, minimumVersion: TLSProtocolVersion, result: (Client) -> ())
    {
        let configuration = TLSConfiguration(supportedVersions: [highestSupportedVersion, minimumVersion])
        let serverHello = TLSServerHello(serverVersion: version,
                                         random: Random(),
                                         sessionID: nil,
                                         cipherSuite: .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
        
        
        let client = Client(configuration: configuration)
        client.stateMachine = nil
        
        do {
            try client.sendClientHello()
            try client.handleHandshakeMessage(serverHello)
        } catch _ {
        }
        
        
        result(client)
    }

    func test_receiveServerHello_withUnknownVersion_abortsHandshake() {
        let version = TLSProtocolVersion(major: 10, minor: 10)
        let highestSupportedVersion = TLSProtocolVersion.v1_2

        receiveServerHello(with: version, highestSupportedVersion: highestSupportedVersion, minimumVersion: highestSupportedVersion, result: { (client: Client) in
            XCTAssert(client.hasAbortedHandshake)
        })
    }
    
    func test_receiveServerHello_withLowerVersionThanWeAdvertisedButHigherOrEqualToMinimumSupportedVersion_dropsToMinimumVersion() {
        let version = TLSProtocolVersion.v1_1
        let highestSupportedVersion = TLSProtocolVersion.v1_2
        let minimumVersions = version

        receiveServerHello(with: version, highestSupportedVersion: highestSupportedVersion, minimumVersion: minimumVersions, result: { (client: Client) in
            XCTAssert(client.negotiatedProtocolVersion == version)
        })

    }
    
    func test_TLSClientHello_withTLSVersion1_3_hasCorrectSupportedVersionsExtensionAndLegacyProtocolVersion() {
        
    }
}
