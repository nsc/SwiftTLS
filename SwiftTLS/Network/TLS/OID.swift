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
    case ECPublicKey                                = "1.2.840.10045.2.1"
    case ECDSAWithSHA256                            = "1.2.840.10045.4.3.2"
    
    case RSAEncryption                              = "1.2.840.113549.1.1.1"
    case SHA1WithRSAEncryption                      = "1.2.840.113549.1.1.5"
    case SHA256WithRSAEncryption                    = "1.2.840.113549.1.1.11"
    
    case PKCS7                                      = "1.2.840.113549.1.7"
    case PKCS7_data                                 = "1.2.840.113549.1.7.1"

    case SHA1                                       = "1.3.14.3.2.26"

    case ansip521r1                                 = "1.3.132.0.35"

    case commonName                                 = "2.5.4.3"
    case surName                                    = "2.5.4.4"
    case serialNumber                               = "2.5.4.5"
    case countryName                                = "2.5.4.6"
    case localityName                               = "2.5.4.7"
    case stateOrProvinceName                        = "2.5.4.8"
    case streetAddress                              = "2.5.4.9"
    case organizationName                           = "2.5.4.10"
    case organizationalUnitName                     = "2.5.4.11"
    
    case postalCode                                 = "2.5.4.17"
    
    case certificateExtensionKeyUsage               = "2.5.29.15"
    case certificateExtensionExtKeyUsage            = "2.5.29.37"
    
    init?(id : [Int])
    {
        guard id.count >= 1 else {
            return nil
        }
        
        let identifier = id[1..<id.count].reduce("\(id[0])", combine: {$0 + ".\($1)"})
        self.init(rawValue: identifier)
    }
    
    var identifier : [Int] {
        get {
            return rawValue.characters.split(".").map {Int(String($0))!}
        }
    }
}