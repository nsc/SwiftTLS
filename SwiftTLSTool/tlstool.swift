//
//  main.swift
//  swifttls
//
//  Created by Nico Schmidt on 16.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftTLS

@main struct TLSTool {
    static func main() async {
        let arguments = ProcessInfo.processInfo.arguments
        guard arguments.count >= 2 else {
            print("Error: No command given")
            exit(1)
        }
        
        let command = arguments[1]
        
        do {
            var mode: Mode? = nil
            switch command
            {
            case "client":
                mode = .client
                fallthrough
            case "server":
                if mode == nil {
                    mode = .server
                }
                guard arguments.count > 2 else {
                    print("Error: Missing arguments for subcommand \"\(command)\"")
                    exit(1)
                }
                
                var host: String? = nil
                var port: UInt16 = 443
                var address: IPAddress? = IPv6Address.anyAddress
                var protocolVersion: TLSProtocolVersion? = nil
                var cipherSuite: CipherSuite? = nil
                var certificatePath: String? = nil
                var dhParameters: String? = nil
                
                var argumentIndex : Int = 2
                while true
                {
                    if arguments.count <= argumentIndex {
                        break
                    }
                    
                    let argument = arguments[argumentIndex]
                    
                    argumentIndex += 1
                    
                    
                    switch argument
                    {
                    case "--TLSVersion":
                        if arguments.count <= argumentIndex {
                            throw MyError.Error("Missing argument for --TLSVersion")
                        }
                        
                        let argument = arguments[argumentIndex]
                        argumentIndex += 1
                        
                        switch argument
                        {
                        case "1.0":
                            protocolVersion = .v1_0
                            
                        case "1.1":
                            protocolVersion = .v1_1
                            
                        case "1.2":
                            protocolVersion = .v1_2
                            
                        case "1.3":
                            protocolVersion = .v1_3
                            
                        default:
                            throw MyError.Error("\(argument) is not a valid TLS version")
                        }
                        
                        continue
                        
                    case "--port":
                        if arguments.count <= argumentIndex {
                            throw MyError.Error("Missing argument for --cipherSuite")
                        }
                        
                        let argument = arguments[argumentIndex]
                        argumentIndex += 1
                        
                        if let p = UInt16(argument) {
                            port = p
                        }
                        
                        continue
                        
                    case "--cipherSuite":
                        if arguments.count <= argumentIndex {
                            throw MyError.Error("Missing argument for --cipherSuite")
                        }
                        
                        let argument = arguments[argumentIndex]
                        argumentIndex += 1
                        
                        cipherSuite = CipherSuite(fromString:argument)
                        
                        continue
                        
                    default:
                        break
                    }
                    
                    if mode! == .server {
                        switch argument
                        {
                        case "--address":
                            if arguments.count <= argumentIndex {
                                throw MyError.Error("Missing argument for --address")
                            }
                            
                            let argument = arguments[argumentIndex]
                            argumentIndex += 1
                            
                            address = IPv6Address.addressWithString(argument, port: port)
                        case "--certificate":
                            if arguments.count <= argumentIndex {
                                throw MyError.Error("Missing argument for --certificate")
                            }
                            
                            let argument = arguments[argumentIndex]
                            argumentIndex += 1
                            
                            certificatePath = argument
                            
                        case "--dhParameters":
                            if arguments.count <= argumentIndex {
                                throw MyError.Error("Missing argument for --dhParameters")
                            }
                            
                            let argument = arguments[argumentIndex]
                            argumentIndex += 1
                            
                            dhParameters = argument
                            
                            
                        default:
                            print("Error: Unknown argument \(argument)")
                            exit(1)
                            
                        }
                    }
                    else if mode! == .client {
                        switch argument
                        {
                        case "--connect":
                            if arguments.count <= argumentIndex {
                                throw MyError.Error("Missing argument for --connect")
                            }
                            
                            let argument = arguments[argumentIndex]
                            argumentIndex += 1
                            
                            if argument.contains(":") {
                                let components = argument.components(separatedBy: ":")
                                host = components[0]
                                guard let p = Int(components[1]), p > 0 && p < 65536 else {
                                    throw MyError.Error("\(components[1]) is not a valid port number")
                                }
                                
                                port = UInt16(p)
                            }
                            else {
                                host = argument
                            }
                            
                        default:
                            print("Error: Unknown argument \(argument)")
                            exit(1)
                            
                        }
                    }
                }
                
                if let mode = mode {
                    switch mode
                    {
                    case .client:
                        guard let hostName = host else {
                            print("Error: Missing argument --connect host[:port]")
                            exit(1)
                        }
                        
                        if let version = protocolVersion {
                            var versions: [TLSProtocolVersion]
                            if version == .v1_3 {
                                versions = [.v1_3, .v1_2]
                            }
                            else {
                                versions = [version]
                            }
                            try await connectTo(host: hostName, port: port, supportedVersions: versions, cipherSuite: cipherSuite)
                        }
                        else {
                            try await connectTo(host: hostName, port: port, cipherSuite: cipherSuite)
                        }
                        
                    case .server:
                        if var address = address {
                            address.port = port
                            var supportedVersions: [TLSProtocolVersion]? = nil
                            if let version = protocolVersion {
                                supportedVersions = [version]
                            }
                            
                            await server(address: address, certificatePath: certificatePath!, dhParametersPath: dhParameters, cipherSuite: cipherSuite, supportedVersions: supportedVersions)
                        }
                    }
                }
                
            case "probeCiphers":
                guard arguments.count > 2 else {
                    print("Error: Missing arguments for subcommand \"\(command)\"")
                    exit(1)
                }
                
                var host : String? = nil
                var port : UInt16 = 443
                var protocolVersion = TLSProtocolVersion.v1_3
                
                var argumentIndex : Int = 2
                while true
                {
                    if arguments.count <= argumentIndex {
                        break
                    }
                    
                    let argument = arguments[argumentIndex]
                    
                    argumentIndex += 1
                    
                    switch argument
                    {
                    case "--TLSVersion":
                        if arguments.count <= argumentIndex {
                            throw MyError.Error("Missing argument for --TLSVersion")
                        }
                        
                        let argument = arguments[argumentIndex]
                        argumentIndex += 1
                        
                        switch argument
                        {
                        case "1.0":
                            protocolVersion = .v1_0
                            
                        case "1.1":
                            protocolVersion = .v1_1
                            
                        case "1.2":
                            protocolVersion = .v1_2
                            
                        case "1.3":
                            protocolVersion = .v1_3
                            
                        default:
                            throw MyError.Error("\(argument) is not a valid TLS version")
                        }
                        
                    default:
                        if argument.contains(":") {
                            let components = argument.components(separatedBy: ":")
                            host = components[0]
                            guard let p = Int(components[1]), p > 0 && p < 65536 else {
                                throw MyError.Error("\(components[1]) is not a valid port number")
                            }
                            
                            port = UInt16(p)
                        }
                        else {
                            host = argument
                        }
                    }
                }
                
                guard let hostName = host else {
                    print("Error: Missing argument --connect host[:port]")
                    exit(1)
                }
                
                await probeCipherSuitesForHost(host: hostName, port: port, protocolVersion: protocolVersion)
                
            case "pem":
                guard arguments.count > 2 else {
                    print("Error: Missing arguments for subcommand \"\(command)\"")
                    exit(1)
                }
                
                let file = arguments[2]
                
                let sections = ASN1Parser.sectionsFromPEMFile(file)
                for (name, section) in sections {
                    print("\(name):")
                    ASN1_printObject(section)
                }
                
            case "asn1parse":
                
                guard arguments.count > 2 else {
                    print("Error: Missing arguments for subcommand \"\(command)\"")
                    exit(1)
                }
                
                let file = arguments[2]
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: file)) else {
                    print("Error: No such file \"\(file)\"")
                    exit(1)
                }
                
                if let object = ASN1Parser(data: data).parseObject()
                {
                    ASN1_printObject(object)
                }
                else {
                    print("Error: Could not parse \"\(file)\"")
                }
                
                break
                
            case "p12":
                guard arguments.count > 2 else {
                    print("Error: Missing arguments for subcommand \"\(command)\"")
                    exit(1)
                }
                
                let file = arguments[2]
                let data = try? Data(contentsOf: URL(fileURLWithPath: file))
                if  let data = data,
                    let object = ASN1Parser(data: data).parseObject()
                {
                    if let sequence = object as? ASN1Sequence,
                       let subSequence = sequence[1] as? ASN1Sequence,
                       let oid = subSequence.objects.first as? ASN1ObjectIdentifier, OID(id: oid.identifier) == .pkcs7_data,
                       let taggedObject = subSequence.objects[1] as? ASN1TaggedObject,
                       let octetString = taggedObject.object as? ASN1OctetString
                    {
                        if let o = ASN1Parser(data: octetString.value).parseObject() {
                            ASN1_printObject(o)
                        }
                    }
                }
                else {
                    print("Error: Could not parse \"\(file)\"")
                }
                
                break
                
            case "scan":
                //    scan()
                break
                
            default:
                print("Error: Unknown command \"\(command)\"")
            }
        }
        catch MyError.Error(let message) {
            print("Error: \(message)")
            exit(1)
        }
        catch let error {
            print("Error: \(error)")
            exit(1)
        }
        
    }
    
    func parseASN1()
    {
        let data = try! Data(contentsOf: URL(fileURLWithPath: "embedded.mobileprovision"))
        
        let object = ASN1Parser(data: data).parseObject()
        
        ASN1_printObject(object!)
    }
    
    enum MyError : Error
    {
        case Error(String)
    }
    
    enum Mode {
        case client
        case server
    }
}
