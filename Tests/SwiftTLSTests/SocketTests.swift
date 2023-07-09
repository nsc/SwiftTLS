//
//  SocketTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 09.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import XCTest
@testable import SwiftTLS

class SocketTests: XCTestCase {
//    static var allTests = [
//        ("test_listen_whenClientConnects_callsAcceptBlock", test_listen_whenClientConnects_callsAcceptBlock),
//    ]

    func dont_test_listen_whenClientConnects_callsAcceptBlock() async
    {
        let server = TCPSocket()
        var address = IPv4Address.localAddress
        address.port = UInt16(12345)
        
        let expectation = self.expectation(description: "accept connection successfully")

        let _ = Task.detached { [address] in
            do {
                print("server listen")
                try server.listen(on: address)
                let _ = try await server.acceptConnection()

                expectation.fulfill()
                server.close()
            } catch {
                
            }
        }
        
        sleep(1)
        
        do {
            let client = TCPSocket()
            do {
                try await client.connect(address)

//                await self.fulfillment(of: [expectation], timeout: 50)
                await waitForExpectations(timeout: 50.0, handler: { (error : Error?) -> Void in
                })
          }
            catch let error as SocketError {
                print("\(error)")
                XCTFail()
            }
            catch _ {}
        }

    }
}
