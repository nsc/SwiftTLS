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

        let key = SecKeyCreateFromData(parameters as CFDictionary, data, &error)
        if let k = key {
            self.key = k
        }
        else {
            self.key = nil
            return nil
        }
    }
    
    
    func encryptCBC(var data : [UInt8], IV : [UInt8]) -> [UInt8]?
    {
        let data = NSData(bytesNoCopy: &data, length: data.count, freeWhenDone: false)
        
        let transform: SecTransform = SecEncryptTransformCreate(self.key, nil)
        var success : Bool = false
        success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, nil)
        success = SecTransformSetAttribute(transform, kSecModeCBCKey, true, nil)
        
        if (success) {
            var error : Unmanaged<CFErrorRef>? = nil
            let resultData: SecTransform! = SecTransformExecute(transform, &error)
            
            if resultData == nil {
                print("\(error?.takeUnretainedValue())")
            }
            
            if let data = resultData as? NSData {
                return [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>(data.bytes), count: data.length))
            }
        }
    
        return nil
    }

    private func createTransform(encrypt encrypt : Bool) -> SecTransform
    {
        switch encrypt
        {
        case true:
            return SecEncryptTransformCreate(self.key, nil)

        case false:
            return SecDecryptTransformCreate(self.key, nil)
        }
    }
    
    func encrypt(data : [UInt8]) -> [UInt8]?
    {
        return crypt(encrypt: true, data: data)
    }
    
    func decrypt(data : [UInt8]) -> [UInt8]?
    {
        return crypt(encrypt: false, data: data)
    }
    
    private func crypt(encrypt encrypt: Bool, var data : [UInt8]) -> [UInt8]?
    {
        let data = NSData(bytesNoCopy: &data, length: data.count, freeWhenDone: false)

        if let transform: SecTransform = createTransform(encrypt: encrypt)
        {
            var success : Bool = false
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, data, nil)
            
            if (success) {
                var error : Unmanaged<CFErrorRef>? = nil
                let resultData: AnyObject! = SecTransformExecute(transform, &error)

                if resultData == nil {
                    print("\(error?.takeUnretainedValue())")
                }
                
                if let data = resultData as? NSData {
                    let result = [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>(data.bytes), count: data.length))
                    
                    return result
                }
            }
        }
        
        return nil
    }

}