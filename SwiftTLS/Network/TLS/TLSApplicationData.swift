//
//  TLSApplicationData.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 24.04.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSApplicationData : TLSMessage
{
    var applicationData : [UInt8]
    
    init(applicationData: [UInt8])
    {
        self.applicationData = applicationData
        super.init(type: .ApplicationData)
    }
    
    required init?(inputStream: InputStreamType)
    {
        applicationData = []
        super.init(type: .ApplicationData)
    }
}