//
//  CryptoKey.swift
//
//  Created by Nico Schmidt on 17.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class CryptoKey
{
    private let key : SecKey!
    
    var data : Data! {
        var error : Unmanaged<CFError>? = nil
        if #available(OSX 10.12, *) {
            if let data = SecKeyCopyExternalRepresentation(key, &error) {
                return data as Data
            }
            else {
                print("Error: \(error?.takeRetainedValue())")
                return nil
            }
        } else {
            // Fallback on earlier versions
            return nil
        }
    }
    
    init(key : SecKey)
    {
        self.key = key
    }

    init?(keyType: CipherAlgorithm, keyData: [UInt8])
    {
        var parameters = [String:String]()
        
        switch (keyType)
        {
        case .aes128, .aes256:
            parameters[kSecAttrKeyType as String] = kSecAttrKeyTypeAES as String
        
        default:
            return nil
        }
        
        var keyData = keyData
        let data = Data(bytesNoCopy: &keyData, count: keyData.count, deallocator: .none)
        var error : Unmanaged<CFError>? = nil

        let key = SecKeyCreateFromData(parameters as CFDictionary, data, &error)
        if let k = key {
            self.key = k
        }
        else {
            return nil
        }
    }
    
    
    func encryptCBC(_ data : [UInt8], IV : [UInt8]) -> [UInt8]?
    {
        var data = data
        let nsdata = Data(bytesNoCopy: &data, count: data.count, deallocator: .none)
        
        let transform: SecTransform = SecEncryptTransformCreate(self.key, nil)
        var success : Bool = false
        success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, nsdata, nil)
        success = SecTransformSetAttribute(transform, kSecModeCBCKey, true, nil)
        
        if (success) {
            var error : Unmanaged<CFError>? = nil
            let resultData: SecTransform! = SecTransformExecute(transform, &error)
            
            if resultData == nil {
                print("\(error?.takeUnretainedValue())")
            }
            
            if let data = resultData as? Data {
                return [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>((data as NSData).bytes), count: data.count))
            }
        }
    
        return nil
    }

    private func createTransform(encrypt : Bool) -> SecTransform
    {
        switch encrypt
        {
        case true:
            return SecEncryptTransformCreate(self.key, nil)

        case false:
            return SecDecryptTransformCreate(self.key, nil)
        }
    }
    
    func encrypt(_ data : [UInt8]) -> [UInt8]?
    {
        return crypt(encrypt: true, data: data)
    }
    
    func decrypt(_ data : [UInt8]) -> [UInt8]?
    {
        return crypt(encrypt: false, data: data)
    }
    
    private func crypt(encrypt: Bool, data : [UInt8]) -> [UInt8]?
    {
        var data = data
        let nsdata = Data(bytesNoCopy: &data, count: data.count, deallocator: .none)

        if let transform: SecTransform = createTransform(encrypt: encrypt)
        {
            var success : Bool = false
            success = SecTransformSetAttribute(transform, kSecTransformInputAttributeName, nsdata, nil)
            
            if (success) {
                var error : Unmanaged<CFError>? = nil
                let resultData: AnyObject! = SecTransformExecute(transform, &error)

                if resultData == nil {
                    print("\(error?.takeUnretainedValue())")
                }
                
                if let data = resultData as? Data {
                    let result = [UInt8](UnsafeBufferPointer<UInt8>(start: UnsafePointer<UInt8>((data as NSData).bytes), count: data.count))
                    
                    return result
                }
            }
        }
        
        return nil
    }

}
