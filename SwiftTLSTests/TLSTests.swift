//
//  TSLTests.swift
//  Chat
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
        let certificatePath = NSBundle(forClass: self.dynamicType).URLForResource("mycert.pem", withExtension: nil)!.path!
        let opensslServer = NSTask.launchedTaskWithLaunchPath("/usr/bin/openssl", arguments: ["s_server",  "-cert", certificatePath, "-www",  "-debug", "-cipher", "ALL:NULL" ])
        
        // wait for server to be up
        sleep(1)
        
        var configuration = TLSConfiguration(protocolVersion: TLSProtocolVersion.TLS_v1_2)
//        configuration.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
//        configuration.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
        configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
        let socket = TLSSocket(configuration: configuration)

//        let (host, port) = ("195.50.155.66", 443)
//        let (host, port) = ("85.13.145.53", 443) // nschmidt.name
        let (host, port) = ("127.0.0.1", 4433)
        
        do {
            try socket.connect(IPAddress.addressWithString(host, port: port)!)
            try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: nschmidt.name\r\n\r\n".utf8))
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
    
    func test_clientServerWithCipherSuite(cipherSuite : CipherSuite)
    {
        var configuration = TLSConfiguration(protocolVersion: .TLS_v1_2)
        
        configuration.cipherSuites = [cipherSuite]
        configuration.identity = Identity(name: "Internet Widgits Pty Ltd")!
        configuration.certificatePath = NSBundle(forClass: self.dynamicType).URLForResource("mycert.pem", withExtension: nil)!.path!
        let dhParametersPath = NSBundle(forClass: self.dynamicType).URLForResource("dhparams.pem", withExtension: nil)!.path!
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
        configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
        
        let address = IPv4Address.localAddress()
        address.port = UInt16(12345)
        
        let server = TLSSocket(configuration: configuration, isClient: false)
        
        let client = TLSSocket(protocolVersion: .TLS_v1_2)
        client.context.configuration.cipherSuites = [cipherSuite]
        
        let expectation = self.expectationWithDescription("accept connection successfully")
        
        let serverQueue = dispatch_queue_create("server queue", nil)
        do {
            dispatch_async(serverQueue) {
                do {
                    try server.acceptConnection(address)
                } catch(let error) {
                    XCTFail("\(error)")
                }
            }
            sleep(1)
            
            try client.connect(address)
            expectation.fulfill()
            client.close()
            server.close()
        }
        catch (let error) {
            XCTFail("\(error)")
        }
        
        self.waitForExpectationsWithTimeout(2.0) {
            (error : NSError?) -> Void in
        }
    }
    
    func test_acceptConnection_whenClientConnects_works()
    {
        let cipherSuites : [CipherSuite] = [
            .TLS_RSA_WITH_AES_256_CBC_SHA,
            .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ]
        
        for cipherSuite in cipherSuites {
            test_clientServerWithCipherSuite(cipherSuite)
        }
    }

//    func test_write_withDataSentOverEncryptedConnection_yieldsThatSameDataOnTheOtherEnd()
//    {
//        let serverIdentity = Identity(name: "Internet Widgits Pty Ltd")
//        
//        let server = TLSSocket(protocolVersion: .TLS_v1_2, isClient: false, identity: serverIdentity!)
//        let address = IPv4Address.localAddress()
//        address.port = UInt16(12345)
//        
//        let sentData = [UInt8]("12345678".utf8)
//        var receivedData : [UInt8]? = nil
//
//        let client = TLSSocket(protocolVersion: .TLS_v1_2)
//
//        let expectation = self.expectationWithDescription("receive data")
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
//        client.connect(address) { (error: SocketError?) -> () in
//            client.write(sentData)
//        }
//        
//        self.waitForExpectationsWithTimeout(5.0) {
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
//        var version = TLSProtocolVersion.TLS_v1_0
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
//        var expectation = self.expectationWithDescription("successfully connected")
//        self.waitForExpectationsWithTimeout(50.0, handler: { (error : NSError!) -> Void in
//        })
//
//    }

}
