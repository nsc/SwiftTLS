//
//  main.swift
//  swifttls
//
//  Created by Nico Schmidt on 16.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
//import SwiftTLS
import OpenSSL
import SwiftHelper

func server(port: Int = 443, certificatePath: String, dhParametersPath : String? = nil, cipherSuite: CipherSuite? = nil)
{
    var certificatePath = certificatePath
    certificatePath = (certificatePath as NSString).expandingTildeInPath
    
    print("Listening on port \(port)")
    
    var configuration = TLSConfiguration(protocolVersion: .v1_2)
    
    let cipherSuites : [CipherSuite] = [
        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//        .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
//        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_RSA_WITH_AES_256_CBC_SHA
        ]
    
    configuration.cipherSuites = cipherSuites
//    configuration.identity = Identity(name: "Internet Widgits Pty Ltd")!
    configuration.identity = PEMFileIdentity(pemFile: certificatePath)
    if let dhParametersPath = dhParametersPath {
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
    }
    configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
    
    let server = TLSSocket(configuration: configuration, isClient: false)
    let address = IPv4Address.localAddress()
    address.port = UInt16(port)
    
    while true {
        do {
            let clientSocket = try server.acceptConnection(address)
            
            let data = try clientSocket.read(count: 1024)
            let string = String.fromUTF8Bytes(data)!
            print("Client Request:\n\(string)")
            let contentLength = string.utf8.count
            let response = "HTTP/1.1 200 OK\nConnection: Close\nContent-Length: \(contentLength)\n\n\(string)"
            try clientSocket.write(response)
            clientSocket.close()
        }
        catch(let error) {
            if let tlserror = error as? TLSError {
                switch tlserror {
                case .error(let message):
                    print("Error: \(message)")
                case .alert(let alert, let level):
                    print("Alert: \(level) \(alert)")
                }
                
                continue
            }
            
            
            print("Error: \(error)")
        }
    }
}

func connectTo(host : String, port : Int = 443, protocolVersion: TLSProtocolVersion = .v1_2, cipherSuite : CipherSuite? = nil)
{
    var configuration = TLSConfiguration(protocolVersion: protocolVersion)
    
    if let cipherSuite = cipherSuite {
        configuration.cipherSuites = [cipherSuite]
    }
    else if protocolVersion == .v1_2 {
        configuration.cipherSuites = [
//            .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
//            .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//            .TLS_RSA_WITH_AES_256_CBC_SHA
        ]
    }
    else {
        configuration.cipherSuites = [
            .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            .TLS_RSA_WITH_AES_256_CBC_SHA
        ]
    }
    
    let context = TLSContext(configuration: configuration)
    var socket = TLSSocket(context: context)
    
    do {
        // Connect twice to test session reuse
        for _ in 0..<2 {
            socket = TLSSocket(configuration: configuration)
            socket.context = context

            print("Connecting to \(host):\(port)")
            try socket.connect(hostname: host, port: port)
            
            print("Connection established using cipher suite \(socket.context.cipherSuite!)")
            
            try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8))
            let data = try socket.read(count: 4096)
            print("\(data.count) bytes read.")
            print("\(String.fromUTF8Bytes(data)!)")
            socket.close()
        }
    } catch (let error) {
        print("Error: \(error)")
    }
    
    return
}

func parseASN1()
{
    let data = try! Data(contentsOf: URL(fileURLWithPath: "embedded.mobileprovision"))
    
    let object = ASN1Parser(data: data).parseObject()
    
    ASN1_printObject(object!)
}

func probeCipherSuitesForHost(host : String, port : Int, protocolVersion: TLSProtocolVersion = .v1_2)
{
    class StateMachine : TLSContextStateMachine
    {
        weak var socket : TLSSocket!
        var cipherSuite : CipherSuite!
        init(socket : TLSSocket)
        {
            self.socket = socket
        }
        
        func shouldContinueHandshakeWithMessage(message: TLSHandshakeMessage) -> Bool
        {
            if let hello = message as? TLSServerHello {
                print("\(hello.cipherSuite)")

                return false
            }
            
            return true
        }
        
        func didReceiveAlert(alert: TLSAlertMessage) {
//            print("\(cipherSuite) not supported")
//            print("NO")
        }
    }

    guard let address = IPAddress.addressWithString(host, port: port) else { print("Error: No such host \(host)"); return }

    for cipherSuite in CipherSuite.allValues {
        let socket = TLSSocket(protocolVersion: protocolVersion)
        let stateMachine = StateMachine(socket: socket)
        socket.context.stateMachine = stateMachine

        socket.context.configuration.cipherSuites = [cipherSuite]
        
        do {
            stateMachine.cipherSuite = cipherSuite
            try socket.connect(address)
        } catch let error as SocketError {
            switch error {
            case .closed:
                socket.close()
            
            default:
                print("Error: \(error)")
            }
        }
        catch {
//            print("Unhandled error: \(error)")
        }
    }
}

let arguments = ProcessInfo.processInfo.arguments
guard arguments.count >= 2 else {
    print("Error: No command given")
    exit(1)
}

let command = arguments[1]

enum MyError : Error
{
    case Error(String)
}

enum Mode {
    case client
    case server
}

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
    var port: Int = 443
    var protocolVersion = TLSProtocolVersion.v1_2
    var cipherSuite: CipherSuite? = nil
    var certificatePath: String? = nil
    var dhParameters: String? = nil
    
    do {
        var argumentIndex : Int = 2
        while true
        {
            if arguments.count <= argumentIndex {
                break
            }
            
            var argument = arguments[argumentIndex]
            
            argumentIndex += 1
            
            
            switch argument
            {
            case "--TLSVersion":
                if arguments.count <= argumentIndex {
                    throw MyError.Error("Missing argument for --TLSVersion")
                }
                
                var argument = arguments[argumentIndex]
                argumentIndex += 1
                
                switch argument
                {
                case "1.0":
                    protocolVersion = .v1_0
                    
                case "1.1":
                    protocolVersion = .v1_1
                    
                case "1.2":
                    protocolVersion = .v1_2
                    
                default:
                    throw MyError.Error("\(argument) is not a valid TLS version")
                }
                
                continue

            case "--cipherSuite":
                if arguments.count <= argumentIndex {
                    throw MyError.Error("Missing argument for --cipherSuite")
                }
                
                var argument = arguments[argumentIndex]
                argumentIndex += 1
                
                cipherSuite = CipherSuite(fromString:argument)
                
                continue
                
            default:
                break
            }

            if mode! == .server {
                switch argument
                {
                case "--port":
                    if arguments.count <= argumentIndex {
                        throw MyError.Error("Missing argument for --port")
                    }
                    
                    var argument = arguments[argumentIndex]
                    argumentIndex += 1
                    
                    if let p = Int(argument) {
                        port = p
                    }
                
                case "--certificate":
                    if arguments.count <= argumentIndex {
                        throw MyError.Error("Missing argument for --certificate")
                    }
                    
                    var argument = arguments[argumentIndex]
                    argumentIndex += 1

                    certificatePath = argument
                
                case "--dhParameters":
                    if arguments.count <= argumentIndex {
                        throw MyError.Error("Missing argument for --dhParameters")
                    }
                    
                    var argument = arguments[argumentIndex]
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
                    
                    var argument = arguments[argumentIndex]
                    argumentIndex += 1
                    
                    if argument.contains(":") {
                        let components = argument.components(separatedBy: ":")
                        host = components[0]
                        guard let p = Int(components[1]), p > 0 && p < 65536 else {
                            throw MyError.Error("\(components[1]) is not a valid port number")
                        }
                        
                        port = p
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
    }
    catch MyError.Error(let message) {
        print("Error: \(message)")
        exit(1)
    }

    if let mode = mode {
        switch mode
        {
        case .client:
            guard let hostName = host else {
                print("Error: Missing argument --connect host[:port]")
                exit(1)
            }
            
            connectTo(host: hostName, port: port, protocolVersion: protocolVersion, cipherSuite: cipherSuite)

        case .server:
            server(port: port, certificatePath: certificatePath!, dhParametersPath: dhParameters, cipherSuite: cipherSuite)
        }
    }
    
case "probeCiphers":
    guard arguments.count > 2 else {
        print("Error: Missing arguments for subcommand \"\(command)\"")
        exit(1)
    }
    
    var host : String? = nil
    var port : Int = 443
    var protocolVersion = TLSProtocolVersion.v1_2
    
    do {
        var argumentIndex : Int = 2
        while true
        {
            if arguments.count <= argumentIndex {
                break
            }
            
            var argument = arguments[argumentIndex]
            
            argumentIndex += 1
            
            switch argument
            {
            case "--TLSVersion":
                if arguments.count <= argumentIndex {
                    throw MyError.Error("Missing argument for --TLSVersion")
                }
                
                var argument = arguments[argumentIndex]
                argumentIndex += 1
                
                switch argument
                {
                case "1.0":
                    protocolVersion = .v1_0
                    
                case "1.1":
                    protocolVersion = .v1_1
                    
                case "1.2":
                    protocolVersion = .v1_2
                    
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
                    
                    port = p
                }
                else {
                    host = argument
                }
            }
        }
    }
    catch MyError.Error(let message) {
        print("Error: \(message)")
        exit(1)
    }
    
    guard let hostName = host else {
        print("Error: Missing argument --connect host[:port]")
        exit(1)
    }
    
    probeCipherSuitesForHost(host: hostName, port: port, protocolVersion: protocolVersion)
    
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
            let subSequence = sequence.objects[1] as? ASN1Sequence,
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
    
default:
    print("Error: Unknown command \"\(command)\"")
}
