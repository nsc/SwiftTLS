//
//  TSLTests.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftTLS

class TSLTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    func notest_connectTLS() {
        let certificatePath = Bundle(for: type(of: self)).url(forResource: "mycert.pem", withExtension: nil)!.path
        let opensslServer = Process.launchedProcess(launchPath: "/usr/local/bin/openssl", arguments: ["s_server",  "-cert", certificatePath, "-www",  "-debug", "-cipher", "ALL:NULL" ])
        
        // wait for server to be up
        sleep(1)
        
        var configuration = TLSConfiguration(supportedVersions: [.v1_3])
        
        configuration.cipherSuites = [.TLS_AES_128_GCM_SHA256]
//        configuration.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
//        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        let socket = TLSClientSocket(configuration: configuration)

//        let (host, port) = ("127.0.0.1", 4433)
        
        do {
//            try socket.connect(IPAddress.addressWithString(host, port: port)!)
            try socket.connect(hostname: "localhost", port: 4433)
            try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8))
            let data = try socket.read(count: 100)
            print("\(String(describing: String.fromUTF8Bytes(data)))")
            socket.close()
        }
        catch let error as SocketError {
            print("Error: \(error)")
            XCTFail()
        }
        catch let error {
            print("Error: \(error)")
            XCTFail()
        }
    
        opensslServer.terminate()
    }
    
    func createServer(with cipherSuite: CipherSuite, port: Int) -> TLSServerSocket
    {
        var configuration = TLSConfiguration(supportedVersions: [.v1_3])
        
        configuration.cipherSuites = [cipherSuite]
        configuration.identity = PEMFileIdentity(pemFile: Bundle(for: type(of: self)).url(forResource: "mycert.pem", withExtension: nil)!.path)
        let dhParametersPath = Bundle(for: type(of: self)).url(forResource: "dhparams.pem", withExtension: nil)!.path
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
        configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
        
        return TLSServerSocket(configuration: configuration)
    }
    
    func test_clientServerWithCipherSuite(_ cipherSuite : CipherSuite, serverSupportsEarlyData: Bool = true, clientSupportsEarlyData: Bool = true)
    {
        let supportedVersions: [TLSProtocolVersion] = [.v1_3]
        var clientConfiguration = TLSConfiguration(supportedVersions: supportedVersions)
        clientConfiguration.cipherSuites = [cipherSuite]
        clientConfiguration.earlyData = .supported(maximumEarlyDataSize: 4096)
     
        let server = createServer(with: cipherSuite, port: 12345)
        server.connection.configuration.earlyData = .supported(maximumEarlyDataSize: 4096)
        
        let expectation = self.expectation(description: "accept connection successfully")
        
        let address = IPv4Address.localAddress()
        address.port = UInt16(12345)
        
        var clientContext: TLSClientContext? = nil

        var numberOfTries = 3

        var serverSideClientSocket: SocketProtocol? = nil
        let serverQueue = DispatchQueue(label: "server queue", attributes: [])
        do {
            serverQueue.async {
                do {
                    try server.listen(on: address)
                    
                    for _ in 0..<numberOfTries {
                        var hasSentEarlyData = false
                        serverSideClientSocket = try server.acceptConnection(withEarlyDataResponseHandler: {
                            (earlyData: Data) in
                            
                            hasSentEarlyData = true
                            
                            return Data(bytes: [1,2,3])
                        })
                        if !hasSentEarlyData {
                            try serverSideClientSocket?.write([1,2,3])
                        }
                        serverSideClientSocket?.close()
                    }
                    
                    server.close()
                } catch(let error) {
                    XCTFail("\(error)")
                }
            }
            sleep(1)
            
            var numberOfSuccesses = 0
            for _ in 0..<3 {
                let client = TLSClientSocket(configuration: clientConfiguration, context: clientContext)
                if clientContext == nil {
                    clientContext = client.context as? TLSClientContext
                }
                
                let earlyDataWasSent = try client.connect(hostname: "127.0.0.1", port: Int(address.port), withEarlyData: Data(bytes: [1,2,3]))

                let response = try client.read(count: 3)
                if response == [1,2,3] as [UInt8] {
                    numberOfSuccesses += 1
                }
                client.close()
            }
            
            if numberOfSuccesses == numberOfTries {
                expectation.fulfill()
            }
        }
        catch (let error) {
            XCTFail("\(error)")
        }
        
        self.waitForExpectations(timeout: 30.0) {
            (error : Error?) -> Void in
        }
    }
    
    func test_acceptConnection_whenClientConnectsWithNeitherClientNorServerSupportingEarlyData_works()
    {
        let cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
        
        test_clientServerWithCipherSuite(cipherSuite, serverSupportsEarlyData: false, clientSupportsEarlyData: false)
    }

    func test_acceptConnection_whenClientConnectsWithClientSupportingEarlyDataAndServerRejectingIt_works()
    {
        let cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
        
        test_clientServerWithCipherSuite(cipherSuite, serverSupportsEarlyData: false, clientSupportsEarlyData: true)
    }

    func test_acceptConnection_whenClientConnectsWithServerSupportingEarlyDataButClientNot_works()
    {
        let cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
        
        test_clientServerWithCipherSuite(cipherSuite, serverSupportsEarlyData: true, clientSupportsEarlyData: false)
    }

    func test_acceptConnection_whenClientConnectsWithBothClientAndServerSupportingEarlyData_works()
    {
        let cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
        
        test_clientServerWithCipherSuite(cipherSuite, serverSupportsEarlyData: true, clientSupportsEarlyData: true)
    }
    
    func test_acceptConnection_whenClientConnects_works()
    {
        let cipherSuites : [CipherSuite] = [
//            .TLS_RSA_WITH_AES_256_CBC_SHA,
//            .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
//            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            
//            .TLS_AES_128_GCM_SHA256
            .TLS_AES_256_GCM_SHA384
        ]
        
        for cipherSuite in cipherSuites {
            test_clientServerWithCipherSuite(cipherSuite)
        }
    }

//    func notest_renegotiate()
//    {
//        let cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//        let server = createServer(with: cipherSuite, port: 12345)
//        
//        let client = TLSClientSocket(supportedVersions: [.v1_2])
//        client.connection.configuration.cipherSuites = [cipherSuite]
//        
//        let expectation = self.expectation(description: "accept connection successfully")
//        
//        let address = IPv4Address.localAddress()
//        address.port = UInt16(12345)
//        
//        let serverQueue = DispatchQueue(label: "server queue", attributes: [])
//        do {
//            serverQueue.async {
//                do {
//                    let client = try server.acceptConnection(address)
//                    try client.write([1,2,3])
//                    
//                    while true {
//                        if let data = try? client.read(count: 1024) {
//                            try client.write(data)
//                        }
//                    }
//                } catch(let error) {
//                    XCTFail("\(error)")
//                }
//            }
//            sleep(1)
//            
//            try client.connect(address)
//            let response = try client.read(count: 3)
//            try client.renegotiate()
//            try client.write([1,2,3])
//
//            if response == [1,2,3] as [UInt8] {
//                expectation.fulfill()
//            }
//            client.close()
//            server.close()
//        }
//        catch (let error) {
//            XCTFail("\(error)")
//        }
//        
//        self.waitForExpectations(timeout: 10.0) {
//            (error : Error?) -> Void in
//        }
//    }

//    func test_write_withDataSentOverEncryptedConnection_yieldsThatSameDataOnTheOtherEnd()
//    {
//        let serverIdentity = Identity(name: "Internet Widgits Pty Ltd")
//        
//        let server = TLSSocket(protocolVersion: .v1_2, isClient: false, identity: serverIdentity!)
//        let address = IPv4Address.localAddress()
//        address.port = UInt16(12345)
//        
//        let sentData = [UInt8]("12345678".utf8)
//        var receivedData : [UInt8]? = nil
//
//        let client = TLSSocket(protocolVersion: .v1_2)
//
//        let expectation = self.expectation(withDescription: "receive data")
//        server.listen(address) {
//            (clientSocket, error) -> () in
//            
//            if clientSocket != nil {
//                clientSocket?.read(count: 8) {
//                    (data, error) -> () in
//                    
//                    if data != nil {
//                        receivedData = data
//                    }
//                    
//                    expectation.fulfill()
//                    
//                    client.close()
//                    server.close()
//                }
//            }
//        }
//        
//        sleep(1)
//        
//        try! client.connect(address)
//        try! client.write(sentData)
//        
//        self.waitForExpectations(withTimeout: 5.0) {
//            (error : NSError?) -> Void in
//            
//            if let receivedData = receivedData {
//                XCTAssertEqual(receivedData, sentData)
//            }
//            else {
//                XCTFail("did not received data")
//            }
//        }
//        
//    }

    
//    func test_sendDoubleClientHello__triggersAlert()
//    {
//        class MyContext : TLSConnection
//        {
//            override func _didReceiveHandshakeMessage(message : TLSHandshakeMessage, completionBlock: ((TLSConnectionError?) -> ())?)
//            {
//                if message.handshakeType == .Certificate {
//                    self.sendClientHello()
//                }
//            }
//        }
//        
//        var version = TLSProtocolVersion.v1_0
//        
//        var socket = TLSSocket(protocolVersion: version)
//        var myContext = MyContext(protocolVersion: version, dataProvider: socket, isClient: true)
//        socket.context = myContext
//        var host = "127.0.0.1"
//        var port = 4433
//        
//        socket.connect(IPAddress.addressWithString(host, port: port)!) { (error : TLSSocketError?) -> () in
//        }
//        
//        var expectation = self.expectation(withDescription: "successfully connected")
//        self.waitForExpectations(withTimeout: 50.0, handler: { (error : NSError!) -> Void in
//        })
//
//    }

}
