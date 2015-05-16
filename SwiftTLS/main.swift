//
//  main.swift
//  swifttls
//
//  Created by Nico Schmidt on 16.05.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

var serverIdentity = Identity(name: "Internet Widgits Pty Ltd")

var server = TLSSocket(protocolVersion: .TLS_v1_0, isClient: false, identity: serverIdentity!)
var address = IPv4Address.localAddress()
address.port = UInt16(12345)

server.listen(address) {
    (clientSocket, error) -> () in
    
    if clientSocket != nil {
        while true {
            clientSocket?.read(count: 1024) {
                (data, error) -> () in
                
                if data != nil {
                    clientSocket?.write(data!, completionBlock: nil)
                }
            }
        }
    }
}

dispatch_main()