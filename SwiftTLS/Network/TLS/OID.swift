//
//  OID.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 03.01.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

enum OID : String
{
    case sha1 = "1.3.14.3.2.26"
    case rsaEncryption = "1.2.840.113549.1.1.1"
    case sha256WithRSAEncryption = "1.2.840.113549.1.1.11"
    
    init?(id : [Int])
    {
        guard id.count >= 1 else {
            return nil
        }
        
        let identifier = id[1..<id.count].reduce("\(id[0])", combine: {$0 + ".\($1)"})
        self.init(rawValue: identifier)
    }
}