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
    static var allTests = [
        ("test_receiveClientHello_withLowerUnknownVersion_abortsHandshake", test_receiveClientHello_withLowerUnknownVersion_abortsHandshake),
        ("test_receiveServerHello_withUnknownVersion_abortsHandshake", test_receiveServerHello_withUnknownVersion_abortsHandshake),
        ("test_receiveServerHello_withLowerVersionThanWeAdvertisedButHigherOrEqualToMinimumSupportedVersion_dropsToMinimumVersion", test_receiveServerHello_withLowerVersionThanWeAdvertisedButHigherOrEqualToMinimumSupportedVersion_dropsToMinimumVersion),
    ]

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
        override func sendHandshakeMessage(_ message: TLSHandshakeMessage, appendToTranscript: Bool = true) async throws {
        }
        
        var hasAbortedHandshake: Bool = false
        override func abortHandshake(with alert: TLSAlert) async throws -> Never{
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
        override func sendHandshakeMessage(_ message: TLSHandshakeMessage, appendToTranscript: Bool = true) async throws {
        }
        
        var hasAbortedHandshake: Bool = false
        override func abortHandshake(with alert: TLSAlert) async throws -> Never {
            hasAbortedHandshake = true
            throw Alert()
        }
    }

    func receiveClientHello(with version: TLSProtocolVersion, highestSupportedVersion: TLSProtocolVersion, result: (Server) -> ()) async
    {
        let clientHello = TLSClientHello(configuration: TLSConfiguration(supportedVersions: [version]),
                                         random: Random(),
                                         sessionID: nil,
                                         cipherSuites: [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256])
        
        
        let server = Server(configuration: TLSConfiguration(supportedVersions: [highestSupportedVersion]))
        
        
        
        do {
            _ = try await server.handleHandshakeMessage(clientHello)
        } catch _ {
        }
        
        
        result(server)
    }
    
    // TODO:
    // As of TLS 1.3 we know that there will be no higher legacy version than 1.2. What is actually supposed to happen in this case?
//    func test_receiveClientHello_withHigherUnknownVersion_fallsBackToHighestSupportedVersion() {
//        let version = TLSProtocolVersion(major: 10, minor: 10)
//        let highestSupportedVersion = TLSProtocolVersion.v1_2
//
//        receiveClientHello(with: version, highestSupportedVersion: highestSupportedVersion, result: { (server: Server) in
//            XCTAssert(server.negotiatedProtocolVersion == highestSupportedVersion)
//        })
//    }

    func test_receiveClientHello_withLowerUnknownVersion_abortsHandshake() async {
        let version = TLSProtocolVersion(major: 1, minor: 1)
        let highestSupportedVersion = TLSProtocolVersion.v1_2
        
        await receiveClientHello(with: version, highestSupportedVersion: highestSupportedVersion, result: { (server: Server) in
            XCTAssert(server.hasAbortedHandshake)
        })
    }
    
    func receiveServerHello(with version: TLSProtocolVersion, highestSupportedVersion: TLSProtocolVersion, minimumVersion: TLSProtocolVersion, result: (Client) -> ()) async
    {
        let configuration = TLSConfiguration(supportedVersions: [highestSupportedVersion, minimumVersion])
        let serverHello = TLSServerHello(serverVersion: version,
                                         random: Random(),
                                         sessionID: nil,
                                         cipherSuite: .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
        
        
        let client = Client(configuration: configuration)
        client.stateMachine = nil
        
        do {
            try await client.sendClientHello()
            _ = try await client.handleHandshakeMessage(serverHello)
        } catch _ {
        }
        
        
        result(client)
    }

    func test_receiveServerHello_withUnknownVersion_abortsHandshake() async {
        let version = TLSProtocolVersion(major: 10, minor: 10)
        let highestSupportedVersion = TLSProtocolVersion.v1_2

        await receiveServerHello(with: version, highestSupportedVersion: highestSupportedVersion, minimumVersion: highestSupportedVersion, result: { (client: Client) in
            XCTAssert(client.hasAbortedHandshake)
        })
    }
    
    func test_receiveServerHello_withLowerVersionThanWeAdvertisedButHigherOrEqualToMinimumSupportedVersion_dropsToMinimumVersion() async {
        let version = TLSProtocolVersion.v1_1
        let highestSupportedVersion = TLSProtocolVersion.v1_2
        let minimumVersions = version

        await receiveServerHello(with: version, highestSupportedVersion: highestSupportedVersion, minimumVersion: minimumVersions, result: { (client: Client) in
            XCTAssert(client.negotiatedProtocolVersion == version)
        })

    }
    
//    func test_TLSClientHello_withTLSVersion1_3_hasCorrectSupportedVersionsExtensionAndLegacyProtocolVersion() {
//        
//    }
}
