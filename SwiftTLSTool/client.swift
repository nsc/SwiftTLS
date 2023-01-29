//
//  client.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftTLS

func connectTo(host : String, port : UInt16 = 443, supportedVersions: [TLSProtocolVersion] = [.v1_3, .v1_2], cipherSuite : CipherSuite? = nil) async throws
{
    var configuration: TLSConfiguration
    
    if let cipherSuite = cipherSuite {
        configuration = TLSConfiguration(supportedVersions: cipherSuite.descriptor!.supportedProtocolVersions)
        configuration.cipherSuites = [cipherSuite]
    }
    else {
        configuration = TLSConfiguration(supportedVersions: supportedVersions)
    }
    
    configuration.earlyData = .supported(maximumEarlyDataSize: 4096)
    
    // Connect twice to test session resumption
    var context: TLSClientContext? = nil
    try await BigInt.withContext { _ in
        var client: TLSClient
        for _ in 0..<2 {
            do {
                print("Connecting to \(host):\(port)")
                client = TLSClient(configuration: configuration, context: context)
                
                let requestData = [UInt8]("GET / HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: SwiftTLS\r\nConnection: Close\r\n\r\n".utf8)
                try await client.connect(hostname: host, port: port, withEarlyData: Data(requestData))
                
                let earlyDataState = client.earlyDataState
                print("Early data: \(earlyDataState)")
                
                if context == nil {
                    context = client.context as? TLSClientContext
                }
                
                print("Connection established using cipher suite \(client.cipherSuite!)")
                
                if earlyDataState != .accepted {
                    try await client.write(requestData)
                }
                
                while true {
                    let data = try await client.read(count: 4096)
                    if data.count == 0 {
                        break
                    }
                    
                    _ = data.withUnsafeBytes { buffer in
                        write(1, buffer.baseAddress, buffer.count)
                    }
                    
                    break
                }
            }
            catch (let error) {
                await client.close()
                
                print("Error: \(error)")
            }
        }
    }
}
