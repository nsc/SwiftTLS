//
//  XCTestHelper.swift
//  SwiftTLSTests
//
//  Created by Nico Schmidt on 27.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import XCTest

extension XCTestCase {
    func path(forResource name: String) -> String {
        if let value = ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"],
            value.hasSuffix("Xcode") {
            
            return Bundle(for: type(of: self)).path(forResource: name, ofType: nil)!
        }
        let resourcesPath = "Tests/SwiftTLSTests/Resources/"
        return resourcesPath.appending(name)
    }
    
    #if os(macOS)
    func printAllTests() {
        print("static var allTests = [")
        let c = type(of: self)
        var numberOfMethods: UInt32 = 0
        let methods = UnsafeBufferPointer<Method>(start: class_copyMethodList(c, &numberOfMethods), count: Int(numberOfMethods))
        for method in methods {
            let s = method_getName(method)
            let name = NSStringFromSelector(s)
            
            if name.hasPrefix("test") {
                print("(\"\(name)\", \(name)),")
            }
        }
        print("]")
    }
    #endif
}
