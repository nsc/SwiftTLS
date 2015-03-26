//
//  CryptoKey.swift
//  Chat
//
//  Created by Nico Schmidt on 17.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class CryptoKey
{
    private let key : SecKey
    
    init(key : SecKey)
    {
        self.key = key
    }

//    var canEncrypt : Bool {
//        get {
//            SecKey
//        }
//    }
    
    func encrypt(var data : [UInt8]) -> [UInt8]?
    {
        let data = NSData(bytesNoCopy: &data, length: data.count, freeWhenDone: false)

        if let t = SecEncryptTransformCreate(self.key, nil) {
            var transform: SecTransform = t.takeRetainedValue()
            var success : Bool = false
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, nil) != 0
            
            if (success) {
                var error : Unmanaged<CFErrorRef>? = nil
                var resultData: SecTransform! = SecTransformExecute(transform, &error)

                if resultData == nil {
                    println("\(error?.takeUnretainedValue())")
                }
                
                if let data = resultData as? NSData {
                    return [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>(data.bytes), count: data.length))
                }
            }
        }
        
        return nil
    }
}