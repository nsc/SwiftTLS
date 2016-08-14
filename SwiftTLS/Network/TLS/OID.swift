//
//  OID.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 03.01.16.
//  Copyright © 2016 Nico Schmidt. All rights reserved.
//

import Foundation

//let oids : [Int:Any] = [
//    1 : [
//        2 : [
//            840 : [
//                10045 : [
//                    2 : [
//                        1 : "ECPublicKey"
//                    ],
//                    4 : [
//                        3 : [
//                            2 : "ECDSAWithSHA256"
//                        ]
//                    ]
//                ],
//                113549 : [
//                    1 : [
//                        1 : [
//                            1  : "RSAEncryption",
//                            5  : "SHA1WithRSAEncryption",
//                            11 : "SHA256WithRSAEncryption",
//                            12 : "SHA384WithRSAEncryption",
//                        ],
//                        7 : [
//                            0 : "PKCS7",
//                            1 : "PKCS7_data"
//                        ]
//                    ]
//                ],
//            ]
//        ],
//        3 : [
//            6 : [
//                1 : [
//                    4 : [
//                        1 : [
//                            311 : [
//                                21 : [
//                                    10 : "applicationCertPolicies"
//                                ],
//                                60 : [
//                                    2 : [
//                                        1 : [
//                                            // 1.3.6.1.4.1.311.60.2.1
//                                            2  : "stateOrProvince",
//                                            3  : "jurisdictionOfIncorporationCountryName"
//                                        ]
//                                    ]
//                                ]
//                            ]
//                        ]
//                    ],
//                    5 : [
//                        5 : [
//                            7 : [
//                                1 : [
//                                    1 : "authorityInfoAccess"
//                                ]
//                            ]
//                        ]
//                    ]
//                ]
//            ],
//            14 : [
//                3 : [
//                    2 : [
//                        26 : "SHA1"
//                    ]
//                ]
//            ],
//            132 : [
//                0 : [
//                    35 : "ansip521r1"
//                ]
//            ]
//        ]
//    ],
//    2 : [
//        5 : [
//            4 : [
//                // 1.2.5.4
//                3  : "commonName",
//                4  : "surName",
//                5  : "serialNumber",
//                6  : "countryName",
//                7  : "localityName",
//                8  : "stateOrProvinceName",
//                9  : "streetAddress",
//                10 : "organizationName",
//                11 : "organizationalUnitName",
//                15 : "businessCategory",
//                
//                17 : "postalCode"
//            ],
//            29 : [
//                // 1.2.5.29
//                14 : "subjectKeyIdentifier",
//                15 : "certificateExtensionKeyUsage",
//                17 : "subjectAlternativeName",
//                19 : "crlDistributionPoints",
//                32 : "certificatePolicies",
//                35 : "authorityKeyIdentifier",
//                37 : "certificateExtensionExtKeyUsage"
//            ]
//        ]
//    ]
//]

enum OID : String
{
    case ecPublicKey                                = "1.2.840.10045.2.1"
    case ecdsaWithSHA256                            = "1.2.840.10045.4.3.2"
    
    case rsaEncryption                              = "1.2.840.113549.1.1.1"
    case sha1WithRSAEncryption                      = "1.2.840.113549.1.1.5"
    case sha256WithRSAEncryption                    = "1.2.840.113549.1.1.11"
    case sha384WithRSAEncryption                    = "1.2.840.113549.1.1.12"
    
    case pkcs7                                      = "1.2.840.113549.1.7"
    case pkcs7_data                                 = "1.2.840.113549.1.7.1"
    case pkcs9_emailAddress                         = "1.2.840.113549.1.9.1"
    
    case applicationCertPolicies                    = "1.3.6.1.4.1.311.21.10"
    case stateOrProvince                            = "1.3.6.1.4.1.311.60.2.1.2"
    case jurisdictionOfIncorporationCountryName     = "1.3.6.1.4.1.311.60.2.1.3"

    case authorityInfoAccess                        = "1.3.6.1.5.5.7.1.1"

    case sha1                                       = "1.3.14.3.2.26"

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
    case businessCategory                           = "2.5.4.15"

    case postalCode                                 = "2.5.4.17"
    
    case subjectKeyIdentifier                       = "2.5.29.14"
    case certificateExtensionKeyUsage               = "2.5.29.15"
    case subjectAlternativeName                     = "2.5.29.17"
    case basicConstraints                           = "2.5.29.19"
    case crlDistributionPoints                      = "2.5.29.31"
    case certificatePolicies                        = "2.5.29.32"
    case authorityKeyIdentifier                     = "2.5.29.35"
    case certificateExtensionExtKeyUsage            = "2.5.29.37"

    case sha256                                     = "2.16.840.1.101.3.4.2.1"
    
    init?(id : [Int])
    {
        guard id.count >= 1 else {
            return nil
        }
        
        let identifier = id[1..<id.count].reduce("\(id[0])", {$0 + ".\($1)"})
        if let oid = OID(rawValue: identifier) {
            self = oid
        }
        else {
            print("Error: unknown OID \(identifier)")
            return nil
        }
    }
    
    var identifier : [Int] {
        get {
            return rawValue.characters.split(separator: ".").map {Int(String($0))!}
        }
    }
}
