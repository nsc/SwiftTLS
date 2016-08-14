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

    func test_connectTLS() {
        let certificatePath = Bundle(for: self.dynamicType).url(forResource: "mycert.pem", withExtension: nil)!.path
        let opensslServer = Task.launchedTask(withLaunchPath: "/usr/local/bin/openssl", arguments: ["s_server",  "-cert", certificatePath, "-www",  "-debug", "-cipher", "ALL:NULL" ])
        
        // wait for server to be up
        sleep(1)
        
        var configuration = TLSConfiguration(protocolVersion: TLSProtocolVersion.v1_2)
        configuration.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
//        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        let socket = TLSSocket(configuration: configuration)

        let (host, port) = ("127.0.0.1", 4433)
        
        do {
            try socket.connect(IPAddress.addressWithString(host, port: port)!)
            try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8))
            let data = try socket.read(count: 100)
            print("\(String.fromUTF8Bytes(data))")
            socket.close()
        }
        catch let error as SocketError {
            print("Error: \(error)")
            XCTFail()
        }
        catch {}
    
        opensslServer.terminate()
    }
    
    func test_clientServerWithCipherSuite(_ cipherSuite : CipherSuite)
    {
        var configuration = TLSConfiguration(protocolVersion: .v1_2)
        
        configuration.cipherSuites = [cipherSuite]
        configuration.identity = PEMFileIdentity(pemFile: Bundle(for: self.dynamicType).url(forResource: "mycert.pem", withExtension: nil)!.path)
        let dhParametersPath = Bundle(for: self.dynamicType).url(forResource: "dhparams.pem", withExtension: nil)!.path
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
        configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
        
        let address = IPv4Address.localAddress()
        address.port = UInt16(12345)
        
        let server = TLSSocket(configuration: configuration, isClient: false)
        
        let client = TLSSocket(protocolVersion: .v1_2)
        client.context.configuration.cipherSuites = [cipherSuite]
        
        let expectation = self.expectation(description: "accept connection successfully")
        
        let serverQueue = DispatchQueue(label: "server queue", attributes: [])
        do {
            serverQueue.async {
                do {
                    let client = try server.acceptConnection(address)
                    try client.write([1,2,3])
                } catch(let error) {
                    XCTFail("\(error)")
                }
            }
            sleep(1)
            
            try client.connect(address)
            let response = try client.read(count: 3)
            if response == [1,2,3] as [UInt8] {
                expectation.fulfill()
            }
            client.close()
            server.close()
        }
        catch (let error) {
            XCTFail("\(error)")
        }
        
        self.waitForExpectations(timeout: 2.0) {
            (error : Error?) -> Void in
        }
    }
    
    func test_acceptConnection_whenClientConnects_works()
    {
        let cipherSuites : [CipherSuite] = [
//            .TLS_RSA_WITH_AES_256_CBC_SHA,
//            .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
//            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ]
        
        for cipherSuite in cipherSuites {
            test_clientServerWithCipherSuite(cipherSuite)
        }
    }

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
//        class MyContext : TLSContext
//        {
//            override func _didReceiveHandshakeMessage(message : TLSHandshakeMessage, completionBlock: ((TLSContextError?) -> ())?)
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
