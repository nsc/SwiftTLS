//
//  TLSServerKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSServerKeyExchange : TLSHandshakeMessage
{
    var dh_p : [UInt8]
    var dh_g : [UInt8]
    var dh_Ys : [UInt8]
    
    var signedParameters : [UInt8]
    
    init(p : BigInt, g : BigInt, Ys : BigInt)
    {
        self.dh_p   = BigIntImpl<UInt8>(p).parts.reverse()
        self.dh_g   = BigIntImpl<UInt8>(g).parts.reverse()
        self.dh_Ys  = BigIntImpl<UInt8>(Ys).parts.reverse()
        
        self.signedParameters = []
        
        super.init(type: .Handshake(.ServerKeyExchange))
    }
    
    required init?(inputStream : InputStreamType)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream) where type == TLSHandshakeType.ServerKeyExchange,
            let dh_pDataLength : UInt16 = inputStream.read(),
            let dh_pData : [UInt8] = inputStream.read(count: Int(dh_pDataLength)),
            let dh_gDataLength : UInt16 = inputStream.read(),
            let dh_gData : [UInt8] = inputStream.read(count: Int(dh_gDataLength)),
            let dh_YsDataLength : UInt16 = inputStream.read(),
            let dh_YsData : [UInt8] = inputStream.read(count: Int(dh_YsDataLength)),
            let signedParametersLength : UInt16 = inputStream.read(),
            let signedParameters : [UInt8] = inputStream.read(count: Int(signedParametersLength))
        else {
            self.dh_p = []
            self.dh_g = []
            self.dh_Ys = []
            self.signedParameters = []
            
            super.init(type: .Handshake(.ServerKeyExchange))
            
            return nil
        }
        
        self.dh_p               = dh_pData
        self.dh_g               = dh_gData
        self.dh_Ys              = dh_YsData
        self.signedParameters   = signedParameters
        
        assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.count + 2)
        
        super.init(type: .Handshake(.ServerKeyExchange))
        
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        self.writeHeader(type: .ServerKeyExchange, bodyLength: self.dh_p.count + self.dh_g.count + self.dh_Ys.count + 6, target: &target)
        target.write(UInt16(self.dh_p.count))
        target.write(self.dh_p)
        
        target.write(UInt16(self.dh_g.count))
        target.write(self.dh_g)
        
        target.write(UInt16(self.dh_Ys.count))
        target.write(self.dh_Ys)

        target.write(UInt16(self.signedParameters.count))
        target.write(self.signedParameters)
    }
}
