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
        
        var socket = TLSSocket(protocolVersion: TLSProtocolVersion.TLS_v1_2)
//        var host = "195.50.155.66"
        var host = "85.13.137.205"
        socket.connect(IPAddress.addressWithString(host, port: 443)!, completionBlock: { (error : TLSSocketError?) -> () in
            expectation.fulfill()
        })
        
        self.waitForExpectationsWithTimeout(2.0, handler: { (error : NSError!) -> Void in
            
        })
    }

}
