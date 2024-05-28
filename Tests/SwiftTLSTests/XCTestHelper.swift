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
        if let value = ProcessInfo.processInfo.environment["XCTestBundlePath"] {
            return Bundle(for: type(of: self)).path(forResource: name, ofType: nil)!
        }
        else if let value = ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"],
        // Xcode pre 11.4
        value.contains("com.apple.dt") ||
        // Xcode >= 11.4
        (value.contains("com.apple.xpc.launchd") && value.hasSuffix("Xcode")) {
            
            return Bundle(for: type(of: self)).path(forResource: name, ofType: nil)!
        }

        let resourcesPath = "Tests/SwiftTLSTests/Resources/"
        return resourcesPath.appending(name)
    }
    
    #if os(macOS)
    func allTestMethodNames() -> [String] {
        var methodNames: [String] = []
        
        let c = type(of: self)
        var numberOfMethods: UInt32 = 0
        let methods = UnsafeBufferPointer<Method>(start: class_copyMethodList(c, &numberOfMethods), count: Int(numberOfMethods))
        for method in methods {
            let s = method_getName(method)
            let name = NSStringFromSelector(s)
            
            // If the method starts with "test" and has return type void ('v' == 0x76)
            if name.hasPrefix("test") && method_copyReturnType(method).pointee == Int8(0x76) {
                methodNames.append(name)
            }
        }
        
        return methodNames
    }
    
    func printAllTests() {
        print("static var allTests = [")
        for methodName in allTestMethodNames() {
            print("(\"\(methodName)\", \(methodName)),")
        }
        print("]")
    }
    #endif
}
