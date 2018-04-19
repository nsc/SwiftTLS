//
//  TLSChangeCipherSpec.swift
//
//  Created by Nico Schmidt on 25.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSChangeCipherSpec : TLSMessage
{
    init()
    {
        super.init(type: .changeCipherSpec)
    }
    
    required init?(inputStream: InputStreamType, context: TLSConnection) {
        if let type: UInt8 = inputStream.read() {
            if type == 1 {
                super.init(type: .changeCipherSpec)
                return
            }
        }

        return nil
    }
    
    override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write(TLSChangeCipherSpecType.changeCipherSpec.rawValue)
    }
}
