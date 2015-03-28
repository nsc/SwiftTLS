//
//  NSDataVsArrayPerformanceTests.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 28.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Cocoa
import XCTest

class NSDataVsArrayPerformanceTests: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func test_appendToNSData()
    {
        var data = NSMutableData()
        
        self.measureBlock() {
            var bytes : [UInt8] = [1,2,3,4,5]
            for var i = 0; i < 100000; ++i {
                data.appendBytes(&bytes, length: 5)
            }
        }
    }

    func test_appendToArrayData()
    {
        var data = [UInt8]()
        
        self.measureBlock() {
            var bytes : [UInt8] = [1,2,3,4,5]
            for var i = 0; i < 100000; ++i {
                data.extend(bytes)
            }
        }
    }

}
