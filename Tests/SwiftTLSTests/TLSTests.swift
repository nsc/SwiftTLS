//
//  TSLTests.swift
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class TLSTests: XCTestCase {
    static var allTests = [
        ("test_acceptConnection_whenClientConnectsWithNeitherClientNorServerSupportingEarlyData_works", test_acceptConnection_whenClientConnectsWithNeitherClientNorServerSupportingEarlyData_works),
        ("test_acceptConnection_whenClientConnectsWithClientSupportingEarlyDataAndServerRejectingIt_works", test_acceptConnection_whenClientConnectsWithClientSupportingEarlyDataAndServerRejectingIt_works),
        ("test_acceptConnection_whenClientConnectsWithServerSupportingEarlyDataButClientNot_works", test_acceptConnection_whenClientConnectsWithServerSupportingEarlyDataButClientNot_works),
        ("test_acceptConnection_whenClientConnectsWithBothClientAndServerSupportingEarlyData_works", test_acceptConnection_whenClientConnectsWithBothClientAndServerSupportingEarlyData_works),
        ("test_acceptConnection_whenClientConnects_works", test_acceptConnection_whenClientConnects_works),
        ("test_acceptConnection_whenClientConnectsWithFragmentedRecords_works", test_acceptConnection_whenClientConnectsWithFragmentedRecords_works),
    ]

    override func setUp() {
        var ctx = BigIntContext()
        ctx.open()
        _ = BigIntContext.setContext(ctx)
    }
    
    override func tearDown() {
        _ = BigIntContext.setContext(nil)
    }
    

    func notest_connectTLS() {
        let certificatePath = path(forResource: "mycert.pem")
        let opensslServer = Process.launchedProcess(launchPath: "/usr/local/bin/openssl", arguments: ["s_server",  "-cert", certificatePath, "-www",  "-debug", "-cipher", "ALL:NULL" ])
        
        // wait for server to be up
        sleep(1)
        
        var configuration = TLSConfiguration(supportedVersions: [.v1_3])
        
        configuration.cipherSuites = [.TLS_AES_128_GCM_SHA256]
//        configuration.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
//        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        let client = TLSClient(configuration: configuration)

//        let (host, port) = ("127.0.0.1", 4433)
        
        do {
//            try socket.connect(IPAddress.addressWithString(host, port: port)!)
            try client.connect(hostname: "localhost", port: 4433)
            try client.write([UInt8]("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8))
            let data = try client.read(count: 100)
            print("\(String(describing: String.fromUTF8Bytes(data)))")
            client.close()
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
    
    func createServer(with cipherSuite: CipherSuite, port: Int, supportedVersions: [TLSProtocolVersion]) -> TLSServer
    {
        var configuration = TLSConfiguration(supportedVersions: supportedVersions)
        
        configuration.cipherSuites = [cipherSuite]
        configuration.identity = PEMFileIdentity(pemFile: path(forResource: "mycert.pem"))
        let dhParametersPath = path(forResource: "dhparams.pem")
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
        configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
        
        return TLSServer(configuration: configuration)
    }
    
    func test_clientServerWithCipherSuite(_ cipherSuite : CipherSuite, serverSupportsEarlyData: Bool = true, clientSupportsEarlyData: Bool = true, maximumRecordSize: Int? = nil)
    {
        guard let supportedVersions = cipherSuite.descriptor?.supportedProtocolVersions else {
            XCTFail("Error: unsupported cipher suite \(cipherSuite)")
            return
        }
        
        var clientConfiguration = TLSConfiguration(supportedVersions: supportedVersions)
        clientConfiguration.cipherSuites = [cipherSuite]
        clientConfiguration.earlyData = clientSupportsEarlyData ? .supported(maximumEarlyDataSize: 4096) : .notSupported
        clientConfiguration.maximumRecordSize = maximumRecordSize
        
        let server = createServer(with: cipherSuite, port: 12345, supportedVersions: supportedVersions)
        server.configuration.earlyData = serverSupportsEarlyData ? .supported(maximumEarlyDataSize: 4096) : .notSupported
        server.configuration.maximumRecordSize = maximumRecordSize

        let expectation = self.expectation(description: "accept connection successfully")
        
        var address = IPv4Address.localAddress
        address.port = UInt16(12345)
        
        var clientContext: TLSClientContext? = nil

        let numberOfTries = 3

        var serverSideClientSocket: SocketProtocol? = nil
        let serverQueue = DispatchQueue(label: "server queue", attributes: [])
        do {
            serverQueue.async {
                do {
                    try server.listen(on: address)
                    
                    for _ in 0..<numberOfTries {
                        var hasSentEarlyData = false
                        serverSideClientSocket = try server.acceptConnection(withEarlyDataResponseHandler: {
                            (connection: TLSConnection, earlyData: Data) in
                            
                            hasSentEarlyData = true
                            
                            return Data([3,4,5])
                        })
                        if !hasSentEarlyData {
                            try serverSideClientSocket?.write([3,4,5])
                        }

                        try serverSideClientSocket?.write([4,5,6])

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
                let client = TLSClient(configuration: clientConfiguration, context: clientContext)
                if clientContext == nil {
                    clientContext = client.context as? TLSClientContext
                }
                
                let _ = try client.connect(hostname: "127.0.0.1", port: address.port, withEarlyData: Data([1,2,3]))

                let response = try client.read(count: 3)
                if response == [3,4,5] as [UInt8] {
                    let response = try client.read(count: 3)
                    if response == [4,5,6] as [UInt8] {
                        numberOfSuccesses += 1
                    }
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
            .TLS_RSA_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            
            .TLS_AES_128_GCM_SHA256,
//            .TLS_AES_256_GCM_SHA384
        ]
        
        for cipherSuite in cipherSuites {
            test_clientServerWithCipherSuite(cipherSuite)
        }
    }

    func test_acceptConnection_whenClientConnectsWithFragmentedRecords_works()
    {
        let cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
        
        test_clientServerWithCipherSuite(cipherSuite, serverSupportsEarlyData: false, clientSupportsEarlyData: false, maximumRecordSize: 100)
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
