//
//  TSLTests.swift
//  Chat
//
//  Created by Nico Schmidt on 14.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

class TSLTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    func test_connectTLS() {
        let expectation = self.expectationWithDescription("successfully connected")

        let opensslServer = NSTask.launchedTaskWithLaunchPath("/usr/bin/openssl", arguments: ["s_server",  "-cert", "SwiftTLSTests/mycert.pem", "-www",  "-debug", "-cipher", "ALL:NULL" ])

        // wait for server to be up
        sleep(1)
        
        let socket = TLSSocket(protocolVersion: TLSProtocolVersion.TLS_v1_0)
//        var host = "195.50.155.66"
//        var host = "85.13.137.205" // nschmidt.name
        let host = "127.0.0.1"
        let port = 4433
//        var port = 443
        
        socket.connect(IPAddress.addressWithString(host, port: port)!, completionBlock: { (error : SocketError?) -> () in
            socket.write([UInt8]("GET / HTTP/1.1\r\nHost: nschmidt.name\r\n\r\n".utf8), completionBlock: { (error : SocketError?) -> () in
                socket.read(count: 4096, completionBlock: { (data, error) -> () in
                    print("\(NSString(bytes: data!, length: data!.count, encoding: NSUTF8StringEncoding)!)")
                    socket.close()
                    expectation.fulfill()
                })
            })
            
            return
        })
        
        self.waitForExpectationsWithTimeout(50.0, handler: { (error : NSError?) -> Void in
        })
        
        opensslServer.terminate()
    }
    
    func test_listen_whenClientConnects_callsAcceptBlock()
    {
        let serverIdentity = Identity(name: "Internet Widgits Pty Ltd")

        let server = TLSSocket(protocolVersion: .TLS_v1_0, isClient: false, identity: serverIdentity!)
        let address = IPv4Address.localAddress()
        address.port = UInt16(12345)
        
        let client = TLSSocket(protocolVersion: .TLS_v1_0)

        let expectation = self.expectationWithDescription("accept connection successfully")
        server.listen(address, acceptBlock: { (clientSocket, error) -> () in
            if clientSocket != nil {
                expectation.fulfill()
                client.close()
                server.close()
            }
            else {
                XCTFail("Connect failed")
            }
        })
        
        client.connect(address) {
            (error: SocketError?) -> () in
            
            if error != nil {
                print("\(error)")
            }
        }
        
        self.waitForExpectationsWithTimeout(2.0) {
            (error : NSError?) -> Void in
        }
    }
    
    func test_write_withDataSentOverEncryptedConnection_yieldsThatSameDataOnTheOtherEnd()
    {
        let serverIdentity = Identity(name: "Internet Widgits Pty Ltd")
        
        let server = TLSSocket(protocolVersion: .TLS_v1_0, isClient: false, identity: serverIdentity!)
        let address = IPv4Address.localAddress()
        address.port = UInt16(12345)
        
        let sentData = [UInt8]("12345678".utf8)
        var receivedData : [UInt8]? = nil

        let client = TLSSocket(protocolVersion: .TLS_v1_0)

        let expectation = self.expectationWithDescription("receive data")
        server.listen(address) {
            (clientSocket, error) -> () in
            
            if clientSocket != nil {
                clientSocket?.read(count: 8) {
                    (data, error) -> () in
                    
                    if data != nil {
                        receivedData = data
                    }
                    
                    expectation.fulfill()
                    
                    client.close()
                    server.close()
                }
            }
        }
        
        client.connect(address) { (error: SocketError?) -> () in
            client.write(sentData)
        }
        
        self.waitForExpectationsWithTimeout(5.0) {
            (error : NSError?) -> Void in
            
            if let receivedData = receivedData {
                XCTAssertEqual(receivedData, sentData)
            }
            else {
                XCTFail("did not received data")
            }
        }
        
    }

    
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
