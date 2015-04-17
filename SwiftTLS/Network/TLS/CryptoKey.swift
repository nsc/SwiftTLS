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
    private let key : SecKey!
    
    init(key : SecKey)
    {
        self.key = key
    }

    init?(keyType: CipherAlgorithm, var keyData: [UInt8])
    {
        var parameters = [String:String]()
        
        switch (keyType)
        {
        case .TRIPLE_DES:
            parameters[kSecAttrKeyType as String] = kSecAttrKeyType3DES as String
            
        case .AES:
            parameters[kSecAttrKeyType as String] = kSecAttrKeyTypeAES as String
        
        default:
            self.key = nil
            return nil
        }
        
        let data = NSData(bytesNoCopy: &keyData, length: keyData.count, freeWhenDone: false)
        var error : Unmanaged<CFErrorRef>? = nil

        var key = SecKeyCreateFromData(parameters as CFDictionary, data, &error)
        if let k = key {
            self.key = key.takeRetainedValue()
        }
        else {
            self.key = nil
            return nil
        }
    }
    

    
    func encryptCBC(var data : [UInt8], IV : [UInt8]) -> [UInt8]?
    {
        let data = NSData(bytesNoCopy: &data, length: data.count, freeWhenDone: false)
        
        if let t = SecEncryptTransformCreate(self.key, nil) {
            var transform: SecTransform = t.takeRetainedValue()
            var success : Bool = false
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, nil) != 0
            success = SecTransformSetAttribute(transform, kSecModeCBCKey.takeUnretainedValue(), true, nil) != 0
            
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

    func encrypt(var data : [UInt8]) -> [UInt8]?
    {
        let data = NSData(bytesNoCopy: &data, length: data.count, freeWhenDone: false)

        if let t = SecEncryptTransformCreate(self.key, nil) {
            var transform: SecTransform = t.takeRetainedValue()
            var success : Bool = false
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, nil) != 0
            
            if (success) {
                var error : Unmanaged<CFErrorRef>? = nil
                var resultData: AnyObject! = SecTransformExecute(transform, &error)

                if resultData == nil {
                    println("\(error?.takeUnretainedValue())")
                }
                
                if let data = resultData as? NSData {
                    var result = [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>(data.bytes), count: data.length))
                    
                    return result
                }
            }
        }
        
        return nil
    }
}