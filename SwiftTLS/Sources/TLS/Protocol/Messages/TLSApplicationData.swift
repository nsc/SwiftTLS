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
        super.init(type: .applicationData)

        self.rawMessageData = applicationData
    }
    
    // FIXME: This constructor is only needed to fulfill the TLSMessage requirement
    required init?(inputStream: InputStreamType, context: TLSConnection)
    {
        fatalError("This method is not implemented")
    }
}
