//
//  Utilities.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 05/02/16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

extension Data {
    func UInt8Array() -> [UInt8] {
        return withUnsafeBytes { bytes in
            return [UInt8](bytes.bindMemory(to: UInt8.self))
        }
    }
}

extension Array where Element == UInt8 {
    init(_ data: Data) {
        self.init(repeating: 0, count: data.count)
        self.withUnsafeMutableBufferPointer {
            _ = data.copyBytes(to: $0)
        }
    }
}
