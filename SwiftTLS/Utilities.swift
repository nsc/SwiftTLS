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
        return [UInt8](UnsafeBufferPointer<UInt8>(start: (self as NSData).bytes.assumingMemoryBound(to: UInt8.self), count: self.count))
    }
}
