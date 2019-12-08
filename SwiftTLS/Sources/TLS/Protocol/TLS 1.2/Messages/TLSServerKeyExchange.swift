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
    
    var publicKey: [UInt8] {
        return Ys.asBigEndianData()
    }
    
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
    public func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
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

enum NumericECCurveType : UInt8
{
    case explicitPrime = 1
    case explicitChar2 = 2
    case namedCurve    = 3
}

enum ECCurveType
{
    var numericECCurveType : NumericECCurveType {
        switch self {
        case .explicitPrime: return NumericECCurveType.explicitPrime
        case .explicitChar2: return NumericECCurveType.explicitChar2
        case .namedCurve(_): return NumericECCurveType.namedCurve
        }
    }
    
    case explicitPrime
    case explicitChar2
    case namedCurve(NamedGroup)
}

public struct ECDiffieHellmanParameters
{
    var curveType : ECCurveType
    
    var publicKey : EllipticCurvePoint!
    
    var curve : EllipticCurve {
        get {
            switch self.curveType
            {
            case .namedCurve(let namedCurve):
                guard let curve = EllipticCurve.named(namedCurve) else {
                    fatalError("Unsuppored curve \(namedCurve)")
                }
                return curve
                
            default:
                fatalError("Unsupported curve type \(self.curveType)")
            }
        }
    }
    
    public init(namedCurve: NamedGroup)
    {
        self.curveType = .namedCurve(namedCurve)
    }
    
    init?(inputStream : InputStreamType)
    {
        guard
            let rawCurveType : UInt8 = inputStream.read(),
            let numericCurveType = NumericECCurveType(rawValue: rawCurveType)
        else {
            return nil
        }
        
        switch numericCurveType
        {
        case .namedCurve:
            guard
                let rawNamedCurve : UInt16 = inputStream.read(),
                let namedCurve = NamedGroup(rawValue: rawNamedCurve),
                let rawPublicKeyPoint : [UInt8] = inputStream.read8()
            else {
                return nil
            }
            
            self.curveType = .namedCurve(namedCurve)
            
            // only uncompressed format is currently supported
            if rawPublicKeyPoint[0] != 4 {
                fatalError("Error: only uncompressed curve points are supported")
            }
            
            let numBits = namedCurve.bitLength
            let numBytes = numBits / 8
            let x = BigInt(bigEndianParts: [UInt8](rawPublicKeyPoint[1 ..< 1 + numBytes]))
            let y = BigInt(bigEndianParts: [UInt8](rawPublicKeyPoint[1 + numBytes ..< 1 + 2 * numBytes]))
            self.publicKey = EllipticCurvePoint(x: x, y: y)
        default:
            fatalError("Error: unsupported curve type \(numericCurveType)")
        }
    }
}

extension ECDiffieHellmanParameters : Streamable
{
    public func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        switch self.curveType
        {
        case .namedCurve(let namedCurve):
            
            target.write(self.curveType.numericECCurveType.rawValue)
            target.write(namedCurve.rawValue)
            let Q = self.publicKey
            let curvePointData : [UInt8] = [4] + Q!.x.asBigEndianData() + Q!.y.asBigEndianData()
            target.write8(curvePointData)
            
        default:
            fatalError("Error: unsupported curve type \(curveType)")
        }
    }
}

extension KeyExchangeParameters : Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        switch self
        {
        case .dhe(let dhe):
            dhe.writeTo(&target, context: context)
        
        case .ecdhe(let ecdhe):
            ecdhe.writeTo(&target, context: context)
        }
    }
}

class TLSServerKeyExchange : TLSHandshakeMessage
{
    var parameters : KeyExchangeParameters
    
    var signedParameters : TLSSignedData
    
    var parametersData : [UInt8] {
        get {
            return [UInt8](parameters)
        }
    }

    init(keyExchangeParameters: KeyExchangeParameters, context: TLSServer) throws
    {
        guard let server = context.protocolHandler as? TLS1_2.ServerProtocol else {
            fatalError("Can't construct TLSServerKeyExchange with a \(String(describing: context.protocolHandler))")
        }
        
        self.parameters = keyExchangeParameters
        
        let securityParameters = server.securityParameters
        var data = securityParameters.clientRandom!
        data += securityParameters.serverRandom!
        data += [UInt8](self.parameters)
        
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

    override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        var body = [UInt8]()

        switch parameters {
        case .dhe(let diffieHellmanParameters):
            diffieHellmanParameters.writeTo(&body, context: context)
        
        case .ecdhe(let ecdhParameters):
            ecdhParameters.writeTo(&body, context: context)
        }
        
        self.signedParameters.writeTo(&body, context: context)
        
        self.writeHeader(type: .serverKeyExchange, bodyLength: body.count, target: &target)
        target.write(body)
    }
}
