//
//  HMAC.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 17.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

func HMAC(hash: Hash.Type, secret: [UInt8], data: [UInt8]) -> [UInt8]
{
    let k: [UInt8]
    if secret.count == hash.blockLength {
        k = secret
    }
    else if secret.count < hash.blockLength {
        k = secret + [UInt8](repeating: 0, count: hash.blockLength - secret.count)
    }
    else {
        k = hash.hash(secret)
    }
    
    let ipad = [UInt8](repeating: 0x36, count: hash.blockLength)
    let opad = [UInt8](repeating: 0x5c, count: hash.blockLength)

    let innerHash = hash.hash((k ^ ipad) + data)
    let outerHash = hash.hash((k ^ opad) + innerHash)

    return outerHash
}
