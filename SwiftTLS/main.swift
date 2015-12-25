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
    let serverIdentity = Identity(name: "Internet Widgits Pty Ltd")
    
    var port = 12345
    if Process.arguments.count >= 2 {
        let portString = Process.arguments[1]
        if let portNumber = Int(portString) {
            port = portNumber
        }
    }
    
    print("Listening on port \(port)")
    
    let server = TLSSocket(protocolVersion: .TLS_v1_2, isClient: false, identity: serverIdentity!)
    let address = IPv4Address.localAddress()
    address.port = UInt16(port)
    
    do {
        let clientSocket = try server.acceptConnection(address)
        
        while true {
            let data = try clientSocket.read(count: 1024)
            print(String.fromUTF8Bytes(data)!)
            try clientSocket.write(data)
        }
    }
    catch(let error) {
        print("Error: \(error)")
    }
}

func client()
{
    let socket = TLSSocket(protocolVersion: .TLS_v1_2)
//    socket.context.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
//    socket.context.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
    socket.context.cipherSuites = [.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256]
    
    //        var host = "195.50.155.66"
    let (host, port) = ("85.13.145.53", 443) // nschmidt.name
//    let (host, port) = ("104.85.251.151", 443) // autodesk license server or something
//    let (host, port) = ("127.0.0.1", 4433)
    
    do {
        try socket.connect(IPAddress.addressWithString(host, port: port)!)
        
        try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: nschmidt.name\r\n\r\n".utf8))
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
    
    ASN1_print_recursive(object!)
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

        socket.context.cipherSuites = [cipherSuite]
        
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

client()
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
