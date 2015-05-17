//
//  main.swift
//  swifttls
//
//  Created by Nico Schmidt on 16.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

var serverIdentity = Identity(name: "Internet Widgits Pty Ltd")

var port = 12345
if Process.arguments.count >= 2 {
    let portString = Process.arguments[1]
    if let portNumber = portString.toInt() {
        port = portNumber
    }
}

println("Listening on port \(port)")

var server = TLSSocket(protocolVersion: .TLS_v1_0, isClient: false, identity: serverIdentity!)
var address = IPv4Address.localAddress()
address.port = UInt16(port)

server.listen(address) {
    (clientSocket, error) -> () in
    
    if error != nil {
        println("Error: \(error)")
        exit(-1)
    }
    
    if clientSocket != nil {
        var recursiveBlock : ((data : [UInt8]?, error : SocketError?) -> ())!
        let readBlock = {
            (data : [UInt8]?, error : SocketError?) -> () in
            
            if data != nil {
                clientSocket?.write(data!, completionBlock: nil)
            }
            
            clientSocket?.read(count: 1024, completionBlock: recursiveBlock)

        }
        recursiveBlock = readBlock
        clientSocket?.read(count: 1024, completionBlock: readBlock)
    }
}

dispatch_main()