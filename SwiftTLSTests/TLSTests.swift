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
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_connectTLS() {
        var expectation = self.expectationWithDescription("successfully connected")
        var task = NSTask.launchedTaskWithLaunchPath("/usr/bin/openssl", arguments: ["s_server",  "-cert", "SwiftTLSTests/mycert.pem", "-www",  "-debug", "-cipher", "ALL:NULL" ])

        sleep(1)
        
        var socket = TLSSocket(protocolVersion: TLSProtocolVersion.TLS_v1_0)
//        var host = "195.50.155.66"
//        var host = "85.13.137.205" // nschmidt.name
        var host = "127.0.0.1"
        var port = 4433
//        var port = 443
        
        socket.connect(IPAddress.addressWithString(host, port: port)!, completionBlock: { (error : TLSSocketError?) -> () in
            expectation.fulfill()
        })
        
        self.waitForExpectationsWithTimeout(500.0, handler: { (error : NSError!) -> Void in
            task.terminate()
        })
    }

}
