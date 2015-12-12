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

//func server()
//{
//    let serverIdentity = Identity(name: "Internet Widgits Pty Ltd")
//    
//    var port = 12345
//    if Process.arguments.count >= 2 {
//        let portString = Process.arguments[1]
//        if let portNumber = Int(portString) {
//            port = portNumber
//        }
//    }
//    
//    print("Listening on port \(port)")
//    
//    let server = TLSSocket(protocolVersion: .TLS_v1_2, isClient: false, identity: serverIdentity!)
//    let address = IPv4Address.localAddress()
//    address.port = UInt16(port)
//    
//    server.listen(address) {
//        (clientSocket, error) -> () in
//        
//        if error != nil {
//            print("Error: \(error)")
//            exit(-1)
//        }
//        
//        if clientSocket != nil {
//            var recursiveBlock : ((data : [UInt8]?, error : SocketError?) -> ())!
//            let readBlock = {
//                (data : [UInt8]?, error : SocketError?) -> () in
//                
//                if var data = data {
//                    print(NSString(bytesNoCopy: &data, length: data.count, encoding: NSUTF8StringEncoding, freeWhenDone: false)!)
//                    clientSocket?.write(data, completionBlock: nil)
//                }
//                
//                clientSocket?.read(count: 1024, completionBlock: recursiveBlock)
//                
//            }
//            recursiveBlock = readBlock
//            clientSocket?.read(count: 1024, completionBlock: readBlock)
//        }
//    }
//}
//
//func client()
//{
//    let socket = TLSSocket(protocolVersion: .TLS_v1_2)
////    socket.context.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
//    socket.context.cipherSuites = [.TLS_RSA_WITH_AES_256_CBC_SHA]
//    
//    //        var host = "195.50.155.66"
//    let (host, port) = ("85.13.145.53", 443) // nschmidt.name
////    let (host, port) = ("104.85.251.151", 443) // autodesk license server or something
////    let (host, port) = ("127.0.0.1", 4433)
//    
//    socket.connect(IPAddress.addressWithString(host, port: port)!, completionBlock: { (error : SocketError?) -> () in
//        socket.write([UInt8]("GET / HTTP/1.1\r\nHost: nschmidt.name\r\n\r\n".utf8), completionBlock: { (error : SocketError?) -> () in
//            socket.read(count: 4096, completionBlock: { (data, error) -> () in
//                print("\(NSString(bytes: data!, length: data!.count, encoding: NSUTF8StringEncoding)!)")
//                socket.close()
//            })
//        })
//        
//        return
//    })
//}
//
//func parseASN1()
//{
//    let data = NSData(contentsOfFile: "embedded.mobileprovision")
//    
//    let object = ASN1Parser(data: data!).parseObject()
//    
//    ASN1_print_recursive(object!)
//}
//
//func probeCipherSuitesForHost(host : String, port : Int)
//{
//    class StateMachine : TLSContextStateMachine
//    {
//        var socket : TLSSocket
//        init(socket : TLSSocket)
//        {
//            self.socket = socket
//        }
//        
//        func didSendMessage(message : TLSMessage) {}
//        func didSendHandshakeMessage(message : TLSHandshakeMessage) {}
//        func didSendChangeCipherSpec() {}
//        func didReceiveChangeCipherSpec() {}
//        func didReceiveHandshakeMessage(message : TLSHandshakeMessage)
//        {
//            if let hello = message as? TLSServerHello {
//                print("\(hello.cipherSuite)")
//                self.socket.close()
//            }
//        }
//    }
//    
//    let cipherSuites : [CipherSuite] = [
//        .TLS_RSA_WITH_RC4_128_MD5,
//        .TLS_RSA_WITH_RC4_128_SHA,
//        .TLS_RSA_WITH_3DES_EDE_CBC_SHA,
//        .TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
//        .TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
//        .TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
//        .TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
//        .TLS_DH_anon_WITH_RC4_128_MD5,
//        .TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
//        .TLS_RSA_WITH_AES_128_CBC_SHA,
//        .TLS_DH_DSS_WITH_AES_128_CBC_SHA,
//        .TLS_DH_RSA_WITH_AES_128_CBC_SHA,
//        .TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
//        .TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
//        .TLS_DH_anon_WITH_AES_128_CBC_SHA,
//        .TLS_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_DH_DSS_WITH_AES_256_CBC_SHA,
//        .TLS_DH_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
//        .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
//        .TLS_DH_anon_WITH_AES_256_CBC_SHA,
//        .TLS_RSA_WITH_NULL_SHA256,
//        .TLS_RSA_WITH_AES_128_CBC_SHA256,
//        .TLS_RSA_WITH_AES_256_CBC_SHA256,
//        .TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
//        .TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
//        .TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
//        .TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
//        .TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
//        .TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
//        .TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
//        .TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
//        .TLS_DH_anon_WITH_AES_128_CBC_SHA256,
//        .TLS_DH_anon_WITH_AES_256_CBC_SHA256,
//    ]
//    
//    for cipherSuite in cipherSuites {
//        let socket = TLSSocket(protocolVersion: .TLS_v1_2)
//        let stateMachine = StateMachine(socket: socket)
//        socket.context.stateMachine = stateMachine
//
//        socket.context.cipherSuites = [cipherSuite]
//        socket.connect(IPAddress.addressWithString(host, port: port)!)
//    }
//}

//client()
//probeCipherSuitesForHost("85.13.145.53", port: 443)

//dispatch_main()

let address = IPv4Address.localAddress()
address.port = UInt16(12345)
//let server = TLSSocket(protocolVersion: .TLS_v1_2, isClient: false, identity: Identity(name: "Internet Widgits Pty Ltd")!)
//try server.acceptConnection(address)

do {
    let client = TLSSocket(protocolVersion: .TLS_v1_2)
    try client.connect(address)
    try client.write("abc\n")
    client.close()
} catch let error as SocketError {
    print("Error: \(error)")
}
