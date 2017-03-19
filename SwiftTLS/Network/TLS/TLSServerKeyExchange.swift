//
//  TLSServerKeyExchange.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 21.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum KeyExchangeParameters {
    case dhe(DiffieHellmanParameters)
    case ecdhe(ECDiffieHellmanParameters)
}

public struct DiffieHellmanParameters
{
    var p : BigInt
    var g : BigInt
    var Ys : BigInt
    
    public static func fromPEMFile(_ file : String) -> DiffieHellmanParameters?
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
        
        self.init(p: BigInt(bigEndianParts: dh_pData), g: BigInt(bigEndianParts: dh_gData), Ys: BigInt(bigEndianParts: dh_YsData))
    }
}

extension DiffieHellmanParameters : Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target)
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
    case explicitPrime  = 1
    case explicitChar2  = 2
    case namedCurve     = 3
}

struct ECDiffieHellmanParameters
{
    var curveType : ECCurveType
    var namedCurve : NamedGroup?
    
    var publicKey : EllipticCurvePoint!
    
    var curve : EllipticCurve {
        get {
            switch self.curveType
            {
            case .namedCurve:
                guard let curve = EllipticCurve.named(self.namedCurve!) else {
                    fatalError("Unsuppored curve \(self.namedCurve)")
                }
                return curve
                
            default:
                fatalError("Unsupported curve type \(self.curveType)")
            }
        }
    }
    
    init(namedCurve: NamedGroup)
    {
        self.curveType = .namedCurve
        self.namedCurve = namedCurve
    }
    
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
        case .namedCurve:
            guard
                let rawNamedCurve : UInt16 = inputStream.read(),
                let namedCurve = NamedGroup(rawValue: rawNamedCurve),
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
            let x = BigInt(bigEndianParts: [UInt8](rawPublicKeyPoint[1..<1+numBytes]))
            let y = BigInt(bigEndianParts: [UInt8](rawPublicKeyPoint[1+numBytes..<1+2*numBytes]))
            self.publicKey = EllipticCurvePoint(x: x, y: y)
        default:
            fatalError("Error: unsupported curve type \(curveType)")
        }
    }
}

extension ECDiffieHellmanParameters : Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        switch self.curveType
        {
        case .namedCurve:
            
            target.write(self.curveType.rawValue)
            target.write(self.namedCurve!.rawValue)
            let Q = self.publicKey
            let curvePointData : [UInt8] = [4] + Q!.x.asBigEndianData() + Q!.y.asBigEndianData()
            target.write(UInt8(curvePointData.count))
            target.write(curvePointData)
            
        default:
            fatalError("Error: unsupported curve type \(curveType)")
        }
    }
}

extension KeyExchangeParameters : Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target) {
        switch self
        {
        case .dhe(let dhe):
            dhe.writeTo(&target)
        
        case .ecdhe(let ecdhe):
            ecdhe.writeTo(&target)
        }
    }
}

class TLSServerKeyExchange : TLSHandshakeMessage
{
    var parameters : KeyExchangeParameters
    
    var signedParameters : TLSSignedData
    
    var parametersData : [UInt8] {
        get {
            return DataBuffer(parameters).buffer
        }
    }

    init(keyExchangeParameters: KeyExchangeParameters, context: TLSServer) throws
    {
        guard let server = context.protocolHandler as? TLS1_2.ServerProtocol else {
            fatalError("Can't construct TLSServerKeyExchange with a \(context.protocolHandler)")
        }
        
        self.parameters = keyExchangeParameters
        
        let securityParameters = server.securityParameters
        var data = securityParameters.clientRandom!
        data += securityParameters.serverRandom!
        data += DataBuffer(self.parameters).buffer
        
        self.signedParameters = try TLSSignedData(data: data, context: context)
        
        super.init(type: .handshake(.serverKeyExchange))
    }

    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        guard
            let (type, _) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.serverKeyExchange
        else {
            return nil
        }

        switch TLSCipherSuiteDescriptorForCipherSuite(context.cipherSuite!)!.keyExchangeAlgorithm!
        {

        case .dhe:
            guard
                let diffieHellmanParameters = DiffieHellmanParameters(inputStream: inputStream),
                let signedParameters = TLSSignedData(inputStream: inputStream, context: context)
            else {
                return nil
            }

            self.parameters         = .dhe(diffieHellmanParameters)
            self.signedParameters   = signedParameters
                        
            if context.negotiatedProtocolVersion == .v1_2 {
//                assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.signature.count + 4)
            } else {
//                assert(bodyLength == dh_pData.count + 2 + dh_gData.count + 2 + dh_YsData.count + 2 + signedParameters.signature.count + 2)
            }
            
        case .ecdhe:
            guard let parameters = ECDiffieHellmanParameters(inputStream: inputStream) else { return nil }
            self.parameters = .ecdhe(parameters)
            if let signedParameters = TLSSignedData(inputStream: inputStream, context: context) {
                self.signedParameters = signedParameters
            }
            else {
                return nil
            }

            break
            
        default:
            return nil
        }
        
        super.init(type: .handshake(.serverKeyExchange))
    }

    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        var body = DataBuffer()

        switch parameters {
        case .dhe(let diffieHellmanParameters):
            diffieHellmanParameters.writeTo(&body)
        
        case .ecdhe(let ecdhParameters):
            ecdhParameters.writeTo(&body)
        }
        
        self.signedParameters.writeTo(&body)
        let bodyData = body.buffer
        
        self.writeHeader(type: .serverKeyExchange, bodyLength: bodyData.count, target: &target)
        target.write(bodyData)
    }
}
