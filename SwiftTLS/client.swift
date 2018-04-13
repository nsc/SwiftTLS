//
//  client.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

func connectTo(host : String, port : Int = 443, supportedVersions: [TLSProtocolVersion] = [.v1_3, .v1_2], cipherSuite : CipherSuite? = nil)
{
    var configuration = TLSConfiguration(supportedVersions: supportedVersions)
    
    var cipherSuites: [CipherSuite] = []
    if let cipherSuite = cipherSuite {
        cipherSuites = [cipherSuite]
    }
    else {
        if supportedVersions.contains(.v1_2) {
            cipherSuites.append(contentsOf: [
                .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                .TLS_RSA_WITH_AES_256_CBC_SHA,
                .TLS_RSA_WITH_AES_128_CBC_SHA256,
                ])
        }
        
        if supportedVersions.contains(.v1_3) {
            cipherSuites.append(contentsOf: [
                .TLS_AES_128_GCM_SHA256,
                .TLS_AES_256_GCM_SHA384
                ])
        }
    }
    
    configuration.cipherSuites = cipherSuites
    
    //    let testSessionReuse = false
    //    let testSecureRenegotiation = false
    do {
        //        if testSessionReuse {
        //            // Connect twice to test session reuse
        //            for _ in 0..<2 {
        //                socket = TLSClientSocket(configuration: configuration)
        //
        //                print("Connecting to \(host):\(port)")
        //                try socket.connect(hostname: host, port: port)
        //
        //                print("Connection established using cipher suite \(socket.connection.cipherSuite!)")
        //
        //                try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8))
        //                let data = try socket.read(count: 4096)
        //                print("\(data.count) bytes read.")
        //                print("\(String.fromUTF8Bytes(data)!)")
        //                socket.close()
        //            }
        //        }
        //        else if testSecureRenegotiation {
        //            // Connect twice to test session reuse
        //            print("Connecting to \(host):\(port)")
        //            try socket.connect(hostname: host, port: port)
        //
        //            print("Connection established using cipher suite \(socket.connection.cipherSuite!)")
        //            for _ in 0..<2 {
        ////                for _ in 0..<5 {
        //                    try socket.write([UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8))
        //
        //                    for _ in 0..<1 {
        //                        let data = try socket.read(count: 40960)
        //                        print("\(data.count) bytes read.")
        //                        print("\(String.fromUTF8Bytes(data)!)")
        //                    }
        ////                }
        //
        //                try socket.renegotiate()
        //            }
        //
        //            socket.close()
        //
        //        }
        //        else {
        
        // Connect twice to test session resumption
        var context: TLSClientContext? = nil
        var socket: TLSClientSocket
        for _ in 0..<1 {
            do {
                print("Connecting to \(host):\(port)")
                socket = TLSClientSocket(configuration: configuration, context: context)
                
                let requestData = [UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8)
                let earlyDataWasSent = try socket.connect(hostname: host, port: port, withEarlyData: Data(bytes: requestData))
//                let earlyDataWasSent = false
//                try socket.connect(hostname: host, port: port)

                if context == nil {
                    context = socket.context as? TLSClientContext
                }
                
                print("Connection established using cipher suite \(socket.connection.cipherSuite!)")
                
                if !earlyDataWasSent {
                    try socket.write(requestData)
                }
                
                //                while true {
                let data = try socket.read(count: 4096)
                if data.count == 0 {
                    break
                }
                print("\(data.count) bytes read.")
                print("\(String.fromUTF8Bytes(data)!)")
                //                }
                socket.close()
            }
            catch (let error) {
                socket.close()
                
                print("Error: \(error)")
            }
        }
        //        }
    } catch (let error) {
        print("Error: \(error)")
    }
    
    return
}
