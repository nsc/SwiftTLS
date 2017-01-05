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
    class Context : TLSContext
    {
        private var _negotiatedProtocolVersion: TLSProtocolVersion? = nil
        override var negotiatedProtocolVersion : TLSProtocolVersion? {
            get {
                return _negotiatedProtocolVersion!
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

    func receiveClientHello(with version: TLSProtocolVersion, highestSupportedVersion: TLSProtocolVersion, result: (Context) -> ())
    {
        let clientHello = TLSClientHello(configuration: TLSConfiguration(supportedVersions: [version]),
                                         random: Random(),
                                         sessionID: nil,
                                         cipherSuites: [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256])
        
        
        let context = Context(configuration: TLSConfiguration(supportedVersions: [highestSupportedVersion]), isClient: false)
        
        
        
        do {
            try context.handleServerHandshakeMessage(clientHello)
        } catch _ {
        }
        
        
        result(context)
    }
    
    func test_receiveClientHello_withHigherUnknownVersion_fallsBackToHighestSupportedVersion() {
        let version = TLSProtocolVersion(major: 10, minor: 10)
        let highestSupportedVersion = TLSProtocolVersion.v1_2

        receiveClientHello(with: version, highestSupportedVersion: highestSupportedVersion, result: { (context: Context) in
            XCTAssert(context.negotiatedProtocolVersion == highestSupportedVersion)
        })
    }

    func test_receiveClientHello_withLowerUnknownVersion_abortsHandshake() {
        let version = TLSProtocolVersion(major: 1, minor: 1)
        let highestSupportedVersion = TLSProtocolVersion.v1_1
        
        receiveClientHello(with: version, highestSupportedVersion: highestSupportedVersion, result: { (context: Context) in
            XCTAssert(context.hasAbortedHandshake)
        })
    }
    
    func receiveServerHello(with version: TLSProtocolVersion, highestSupportedVersion: TLSProtocolVersion, minimumVersion: TLSProtocolVersion, result: (Context) -> ())
    {
        let configuration = TLSConfiguration(supportedVersions: [highestSupportedVersion, minimumVersion])
        let serverHello = TLSServerHello(serverVersion: version,
                                         random: Random(),
                                         sessionID: nil,
                                         cipherSuite: .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
        
        
        let context = Context(configuration: configuration, isClient: true)
        context.stateMachine = nil
        
        do {
            try context.sendClientHello()
            try context.handleClientHandshakeMessage(serverHello)
        } catch _ {
        }
        
        
        result(context)
    }

    func test_receiveServerHello_withUnknownVersion_abortsHandshake() {
        let version = TLSProtocolVersion(major: 10, minor: 10)
        let highestSupportedVersion = TLSProtocolVersion.v1_2

        receiveServerHello(with: version, highestSupportedVersion: highestSupportedVersion, minimumVersion: highestSupportedVersion, result: { (context: Context) in
            XCTAssert(context.hasAbortedHandshake)
        })
    }
    
    func test_receiveServerHello_withLowerVersionThanWeAdvertisedButHigherOrEqualToMinimumSupportedVersion_dropsToMinimumVersion() {
        let version = TLSProtocolVersion.v1_1
        let highestSupportedVersion = TLSProtocolVersion.v1_2
        let minimumVersions = version

        receiveServerHello(with: version, highestSupportedVersion: highestSupportedVersion, minimumVersion: minimumVersions, result: { (context: Context) in
            XCTAssert(context.negotiatedProtocolVersion == version)
        })

    }
    
    func test_TLSClientHello_withTLSVersion1_3_hasCorrectSupportedVersionsExtensionAndLegacyProtocolVersion() {
        
    }
}
