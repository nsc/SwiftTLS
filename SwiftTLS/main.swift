//
//  main.swift
//  swifttls
//
//  Created by Nico Schmidt on 16.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

func server()
{
    var serverIdentity = Identity(name: "Internet Widgits Pty Ltd")
    
    var port = 12345
    if Process.arguments.count >= 2 {
        let portString = Process.arguments[1]
        if let portNumber = Int(portString) {
            port = portNumber
        }
    }
    
    print("Listening on port \(port)")
    
    var server = TLSSocket(protocolVersion: .TLS_v1_0, isClient: false, identity: serverIdentity!)
    var address = IPv4Address.localAddress()
    address.port = UInt16(port)
    
    server.listen(address) {
        (clientSocket, error) -> () in
        
        if error != nil {
            print("Error: \(error)")
            exit(-1)
        }
        
        if clientSocket != nil {
            var recursiveBlock : ((data : [UInt8]?, error : SocketError?) -> ())!
            let readBlock = {
                (data : [UInt8]?, error : SocketError?) -> () in
                
                if var data = data {
                    print(NSString(bytesNoCopy: &data, length: data.count, encoding: NSUTF8StringEncoding, freeWhenDone: false)!)
                    clientSocket?.write(data, completionBlock: nil)
                }
                
                clientSocket?.read(count: 1024, completionBlock: recursiveBlock)
                
            }
            recursiveBlock = readBlock
            clientSocket?.read(count: 1024, completionBlock: readBlock)
        }
    }
}

func client()
{
    let socket = TLSSocket(protocolVersion: TLSProtocolVersion.TLS_v1_0)
    socket.context.cipherSuites = [.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
    
    //        var host = "195.50.155.66"
    let host = "85.13.145.53" // nschmidt.name
    //        let host = "127.0.0.1"
    //        let port = 4433
    let port = 443
    
    socket.connect(IPAddress.addressWithString(host, port: port)!, completionBlock: { (error : SocketError?) -> () in
        socket.write([UInt8]("GET / HTTP/1.1\r\nHost: nschmidt.name\r\n\r\n".utf8), completionBlock: { (error : SocketError?) -> () in
            socket.read(count: 4096, completionBlock: { (data, error) -> () in
                print("\(NSString(bytes: data!, length: data!.count, encoding: NSUTF8StringEncoding)!)")
                socket.close()
            })
        })
        
        return
    })
}

client()

dispatch_main()