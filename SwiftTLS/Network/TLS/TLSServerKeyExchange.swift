//
//  TLSServerKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

struct DiffieHellmanParameters
{
    var p : BigInt
    var g : BigInt
    var Ys : BigInt
}

enum ECCurveType : UInt8
{
    case ExplicitPrime  = 1
    case ExplicitChar2  = 2
    case NamedCurve     = 3
}

struct ECDiffieHellmanParameters
{
    var curveType : ECCurveType
    var namedCurve : NamedCurve?
    
    var publicKey : EllipticCurvePoint
    
    init?(inputStream : InputStreamType)
    {
        guard
            let rawCurveType : UInt8 = inputStream.read(),
            let curveType = ECCurveType(rawValue: rawCurveType)
        else {
            return nil
        }
        
        self.curveType = curveType
        
        switch curveType
        {
        case .NamedCurve:
            guard
                let rawNamedCurve : UInt16 = inputStream.read(),
                let namedCurve = NamedCurve(rawValue: rawNamedCurve),
                let rawPublicKeyPoint : [UInt8] = inputStream.read8()
            else {
                return nil
            }
            
            self.namedCurve = namedCurve
            
            // only uncompressed format is currently supported
            if rawPublicKeyPoint[0] != 4 {
                fatalError("Error: only uncompressed curve points are supported")
            }
            
            let numBits = namedCurve.bitLength
            let numBytes = numBits/8
            let x = BigInt([UInt8](rawPublicKeyPoint[1..<1+numBytes]).reverse())
            let y = BigInt([UInt8](rawPublicKeyPoint[1+numBytes..<1+2*numBytes]).reverse())
            self.publicKey = EllipticCurvePoint(x: x, y: y)
        default:
            fatalError("Error: unsupported curve type \(curveType)")
        }
    }
}

class TLSServerKeyExchange : TLSHandshakeMessage
{
    var diffieHellmanParameters : DiffieHellmanParameters?
    var ecDiffieHellmanParameters : ECDiffieHellmanParameters?
    
    var signedParameters : TLSSignedData
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream) where type == TLSHandshakeType.ServerKeyExchange
        else {
            self.signedParameters = TLSSignedData()
            super.init(inputStream: inputStream, context: context)
            
            return nil
        }

        switch TLSCipherSuiteDescriptorForCipherSuite(context.cipherSuite!).keyExchangeAlgorithm
        {

        case .DHE_RSA:
            guard
                let dh_pDataLength : UInt16 = inputStream.read(),
                let dh_pData : [UInt8] = inputStream.read(count: Int(dh_pDataLength)),
                let dh_gDataLength : UInt16 = inputStream.read(),
                let dh_gData : [UInt8] = inputStream.read(count: Int(dh_gDataLength)),
                let dh_YsDataLength : UInt16 = inputStream.read(),
                let dh_YsData : [UInt8] = inputStream.read(count: Int(dh_YsDataLength)),
                let signedParameters = TLSSignedData(inputStream: inputStream, context: context)
            else {
                self.signedParameters = TLSSignedData()
                super.init(inputStream: inputStream, context: context)

                return nil
            }

            self.diffieHellmanParameters = DiffieHellmanParameters(p: BigInt(dh_pData.reverse()), g: BigInt(dh_gData.reverse()), Ys: BigInt(dh_YsData.reverse()))
            self.signedParameters   = signedParameters
            
            if context.negotiatedProtocolVersion == .TLS_v1_2 {
                assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.signature.count + 4)
            } else {
                assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.signature.count + 2)
            }
            
        case .ECDHE_RSA:
            self.ecDiffieHellmanParameters = ECDiffieHellmanParameters(inputStream: inputStream)
            if let signedParameters = TLSSignedData(inputStream: inputStream, context: context) {
                self.signedParameters = signedParameters
            }
            else {
                self.signedParameters = TLSSignedData()
                super.init(inputStream: inputStream, context: context)

                return nil
            }

            break
            
        default:
            self.signedParameters = TLSSignedData()
            break
        }
        
        super.init(type: .Handshake(.ServerKeyExchange))
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        if let diffieHellmanParameters = self.diffieHellmanParameters {
            let dh_p  : [UInt8] = BigIntImpl<UInt8>(diffieHellmanParameters.p).parts.reverse()
            let dh_g  : [UInt8] = BigIntImpl<UInt8>(diffieHellmanParameters.g).parts.reverse()
            let dh_Ys : [UInt8] = BigIntImpl<UInt8>(diffieHellmanParameters.Ys).parts.reverse()
            
            self.writeHeader(type: .ServerKeyExchange, bodyLength: dh_p.count + dh_g.count + dh_Ys.count + 6, target: &target)
            target.write(UInt16(dh_p.count))
            target.write(dh_p)
            
            target.write(UInt16(dh_g.count))
            target.write(dh_g)
            
            target.write(UInt16(dh_Ys.count))
            target.write(dh_Ys)
            
            self.signedParameters.writeTo(&target)
        }
        
        else if let ecDiffieHellmanParameters = self.ecDiffieHellmanParameters {
            
        }
    }
}
