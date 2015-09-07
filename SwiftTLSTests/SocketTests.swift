//
//  SocketTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest
@testable import SwiftTLS

class SocketTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_listen_whenClientConnects_callsAcceptBlock()
    {
        let server = TCPSocket()
        let address = IPv4Address.localAddress()
        address.port = UInt16(12345)
        
        let expectation = self.expectationWithDescription("accept connection successfully")
        server.listen(address, acceptBlock: { (clientSocket, error) -> () in
            if error != nil {
                print("\(error)")
                return
            }
            
            if clientSocket != nil {
                expectation.fulfill()
            }
        })
        
        let client = TCPSocket()
        client.connect(address, completionBlock: { (error: SocketError?) -> () in
            print("\(error)")
        })
        
        self.waitForExpectationsWithTimeout(50.0, handler: { (error : NSError?) -> Void in
        })

        server.close()
        client.close()
    }
}
