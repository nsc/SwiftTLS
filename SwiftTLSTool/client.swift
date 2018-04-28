//
//  client.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftTLS

func connectTo(host : String, port : UInt16 = 443, supportedVersions: [TLSProtocolVersion] = [.v1_3, .v1_2], cipherSuite : CipherSuite? = nil)
{    
    var configuration = TLSConfiguration(supportedVersions: supportedVersions)

    if let cipherSuite = cipherSuite {
        configuration.cipherSuites = [cipherSuite]
    }
    
    // Connect twice to test session resumption
    var context: TLSClientContext? = nil
    var client: TLSClient
    for _ in 0..<2 {
        do {
            print("Connecting to \(host):\(port)")
            client = TLSClient(configuration: configuration, context: context)
            
            let requestData = [UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\nConnection: Close\r\n\r\n".utf8)
            let earlyDataWasSent = try client.connect(hostname: host, port: port, withEarlyData: Data(bytes: requestData))
            
            if context == nil {
                context = client.context as? TLSClientContext
            }
            
            print("Connection established using cipher suite \(client.cipherSuite!)")
            
            if !earlyDataWasSent {
                try client.write(requestData)
            }
            
            let data = try client.read(count: 4096)
            if data.count == 0 {
                break
            }
            print("\(data.count) bytes read.")
            print("\(String.fromUTF8Bytes(data)!)")
        }
        catch (let error) {
            client.close()
            
            print("Error: \(error)")
        }
    }
}
