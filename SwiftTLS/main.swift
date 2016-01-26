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

func server()
{
    var port = 12345
    var certificatePath : String?
    var dhParametersPath : String?
    if Process.arguments.count >= 2 {
        let portString = Process.arguments[1]
        if let portNumber = Int(portString) {
            port = portNumber
        }
    }

    if Process.arguments.count >= 3 {
        certificatePath = Process.arguments[2]
    }

    if Process.arguments.count >= 4 {
        dhParametersPath = Process.arguments[3]
    }
    
    print("Listening on port \(port)")
    
    var configuration = TLSConfiguration(protocolVersion: .TLS_v1_2)
    
    let cipherSuites : [CipherSuite] = [
//        .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_RSA_WITH_AES_256_CBC_SHA
        ]
    
    configuration.cipherSuites = cipherSuites
    configuration.identity = Identity(name: "Internet Widgits Pty Ltd")!
    configuration.certificatePath = certificatePath
    if let dhParametersPath = dhParametersPath {
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
    }
    configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp521r1)
    
    let server = TLSSocket(configuration: configuration, isClient: false)
    let address = IPv4Address.localAddress()
    address.port = UInt16(port)
    
    while true {
        do {
            let clientSocket = try server.acceptConnection(address)
            
            while true {
                let data = try clientSocket.read(count: 1024)
                print(String.fromUTF8Bytes(data)!)
                try clientSocket.write(data)
            }
        }
        catch(let error) {
            if let tlserror = error as? TLSError {
                switch tlserror {
                case .Error(let message):
                    print("Error: \(message)")
                }
                
                continue
            }
            
            
            print("Error: \(error)")
        }
    }
}

func connectTo(host host : String, port : Int = 443)
{
    var configuration = TLSConfiguration(protocolVersion: .TLS_v1_2)
    configuration.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
//    configuration.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
//    configuration.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
    
    let socket = TLSSocket(configuration: configuration)
    
    do {
        try socket.connect(IPAddress.addressWithString(host, port: port)!)
        
        print("Connection established using cipher suite ", socket.context.cipherSuite!)
        
        try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8))
        let data = try socket.read(count: 4096)
        print("\(data.count) bytes read.")
        print("\(String.fromUTF8Bytes(data)!)")
        socket.close()
    } catch (let error) {
        print("Error: \(error)")
    }
    
    return
}

func parseASN1()
{
    let data = NSData(contentsOfFile: "embedded.mobileprovision")
    
    let object = ASN1Parser(data: data!).parseObject()
    
    ASN1_printObject(object!)
}

func probeCipherSuitesForHost(host : String, port : Int)
{
    class StateMachine : TLSContextStateMachine
    {
        var socket : TLSSocket
        var cipherSuite : CipherSuite!
        init(socket : TLSSocket)
        {
            self.socket = socket
        }
        
        func shouldContinueHandshakeWithMessage(message: TLSHandshakeMessage) -> Bool
        {
            if let hello = message as? TLSServerHello {
                print("\(hello.cipherSuite)")
                self.socket.close()

                return false
            }
            
            return true
        }
        
        func didReceiveAlert(alert: TLSAlertMessage) {
//            print("\(cipherSuite) not supported")
//            print("NO")
        }
    }
    
    for cipherSuite in CipherSuite.allValues {
        let socket = TLSSocket(protocolVersion: .TLS_v1_2)
        let stateMachine = StateMachine(socket: socket)
        socket.context.stateMachine = stateMachine

        socket.context.configuration.cipherSuites = [cipherSuite]
        
//        print("\(cipherSuite)\t: ", separator: "", terminator: "")
        do {
            stateMachine.cipherSuite = cipherSuite
            try socket.connect(IPAddress.addressWithString(host, port: port)!)
        } catch _ as SocketError {
//            print("Error: \(error)")
        }
        catch {}
    }
}

guard Process.arguments.count >= 2 else {
    print("Error: No command given")
    exit(1)
}

let command = Process.arguments[1]

switch command
{
case "client":
    guard Process.arguments.count > 2 else {
        print("Error: Missing arguments for subcommand \"\(command)\"")
        exit(1)
    }
    
    if Process.arguments.count == 3 {
        connectTo(host: Process.arguments[2])
    }
    else {
        guard let port = Int(Process.arguments[3]) else {
            print("Error: Malformed port argument for subcommand \"\(command)\"")
            exit(1)
        }
        
        connectTo(host:Process.arguments[2], port: port)
    }
    
    break
    
case "asn1parse":

    guard Process.arguments.count > 2 else {
        print("Error: Missing arguments for subcommand \"\(command)\"")
        exit(1)
    }

    let file = Process.arguments[2]
    let data = NSData(contentsOfFile: file)
    if  let data = data,
        let object = ASN1Parser(data: data).parseObject()
    {
        ASN1_printObject(object)
    }
    else {
        print("Error: Could not parse \"\(file)\"")
    }
    
    break

case "p12":
    
    guard Process.arguments.count > 2 else {
        print("Error: Missing arguments for subcommand \"\(command)\"")
        exit(1)
    }
    
    let file = Process.arguments[2]
    let data = NSData(contentsOfFile: file)
    if  let data = data,
        let object = ASN1Parser(data: data).parseObject()
    {
        if let sequence = object as? ASN1Sequence,
            let subSequence = sequence.objects[1] as? ASN1Sequence,
            let oid = subSequence.objects.first as? ASN1ObjectIdentifier where OID(id: oid.identifier) == .PKCS7_data,
            let taggedObject = subSequence.objects[1] as? ASN1TaggedObject,
            let octetString = taggedObject.taggedObject as? ASN1OctetString
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

//server()
//probeCipherSuitesForHost("77.74.169.27", port: 443)
//probeCipherSuitesForHost("85.13.145.53", port: 443)
//probeCipherSuitesForHost("62.153.105.15", port: 443)

//dispatch_main()

//let address = IPv4Address.localAddress()
//address.port = UInt16(12345)
////let server = TLSSocket(protocolVersion: .TLS_v1_2, isClient: false, identity: Identity(name: "Internet Widgits Pty Ltd")!)
////try server.acceptConnection(address)
//
//do {
//    let client = TLSSocket(protocolVersion: .TLS_v1_2)
//    try client.connect(address)
//    try client.write("abc\n")
//    client.close()
//} catch let error as SocketError {
//    print("Error: \(error)")
//}
