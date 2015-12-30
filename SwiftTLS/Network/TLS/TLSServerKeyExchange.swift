//
//  TLSServerKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public struct DiffieHellmanParameters
{
    var p : BigInt
    var g : BigInt
    var Ys : BigInt
    
    public static func fromPEMFile(file : String) -> DiffieHellmanParameters?
    {
        guard let sequence = ASN1Parser.objectFromPEMFile(file) as? ASN1Sequence else {
            return nil
        }
                
        guard let prime = sequence.objects[0] as? ASN1Integer else {
            return nil
        }
        
        guard let generator = sequence.objects[1] as? ASN1Integer else {
            return nil
        }
        
        let p = BigInt(bigEndianParts: prime.value)
        let g = BigInt(bigEndianParts: generator.value)
        return DiffieHellmanParameters(p: p, g: g, Ys:BigInt(0))
    }
    
    init(p : BigInt, g : BigInt, Ys : BigInt)
    {
        self.p = p
        self.g = g
        self.Ys = Ys
    }
    
    init?(inputStream : InputStreamType)
    {
        guard
            let dh_pDataLength : UInt16 = inputStream.read(),
            let dh_pData : [UInt8] = inputStream.read(count: Int(dh_pDataLength)),
            let dh_gDataLength : UInt16 = inputStream.read(),
            let dh_gData : [UInt8] = inputStream.read(count: Int(dh_gDataLength)),
            let dh_YsDataLength : UInt16 = inputStream.read(),
            let dh_YsData : [UInt8] = inputStream.read(count: Int(dh_YsDataLength))
        else {
            return nil
        }
        
        self.init(p: BigInt(dh_pData.reverse()), g: BigInt(dh_gData.reverse()), Ys: BigInt(dh_YsData.reverse()))
    }
}

extension DiffieHellmanParameters : Streamable
{
    func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        let dh_p  = self.p.asBigEndianData()
        let dh_g  = self.g.asBigEndianData()
        let dh_Ys = self.Ys.asBigEndianData()
        
        target.write(UInt16(dh_p.count))
        target.write(dh_p)
        
        target.write(UInt16(dh_g.count))
        target.write(dh_g)
        
        target.write(UInt16(dh_Ys.count))
        target.write(dh_Ys)
    }
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
    var ecdhParameters : ECDiffieHellmanParameters?
    
    var signedParameters : TLSSignedData
    
    init(dhParameters: DiffieHellmanParameters, context: TLSContext)
    {
        self.diffieHellmanParameters = dhParameters
        
        self.signedParameters = TLSSignedData(data: DataBuffer(dhParameters).buffer, context:context)
        
        super.init(type: .Handshake(.ServerKeyExchange))
    }
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        guard
            let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream) where type == TLSHandshakeType.ServerKeyExchange
        else {
            self.signedParameters = TLSSignedData()
            super.init(inputStream: inputStream, context: context)
            
            return nil
        }

        switch TLSCipherSuiteDescriptorForCipherSuite(context.cipherSuite!)!.keyExchangeAlgorithm
        {

        case .DHE_RSA:
            guard
                let diffieHellmanParameters = DiffieHellmanParameters(inputStream: inputStream),
                let signedParameters = TLSSignedData(inputStream: inputStream, context: context)
            else {
                self.signedParameters = TLSSignedData()
                super.init(inputStream: inputStream, context: context)

                return nil
            }

            self.diffieHellmanParameters    = diffieHellmanParameters
            self.signedParameters           = signedParameters
                        
            if context.negotiatedProtocolVersion == .TLS_v1_2 {
//                assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.signature.count + 4)
            } else {
//                assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.signature.count + 2)
            }
            
        case .ECDHE_RSA:
            self.ecdhParameters = ECDiffieHellmanParameters(inputStream: inputStream)
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
            
            var body = DataBuffer()
            diffieHellmanParameters.writeTo(&body)
            self.signedParameters.writeTo(&body)
            let bodyData = body.buffer
            
            self.writeHeader(type: .ServerKeyExchange, bodyLength: bodyData.count, target: &target)
            target.write(bodyData)
        }
        
        else if let ecdhParameters = self.ecdhParameters {
            assert(false)
        }
    }
}
