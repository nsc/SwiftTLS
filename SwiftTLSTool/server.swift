//
//  server.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftTLS

func server(address: IPAddress, certificatePath: String, dhParametersPath : String? = nil, cipherSuite: CipherSuite? = nil)
{    
    print("Listening on port \(address.port)")
    
    let supportedVersions: [TLSProtocolVersion] = [.v1_2]
    
    var cipherSuites : [CipherSuite] = [
        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        //        .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        .TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        .TLS_RSA_WITH_AES_256_CBC_SHA
    ]
    
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
    
    if let cipherSuite = cipherSuite {
        cipherSuites.insert(cipherSuite, at: 0)
    }
    
    let identity = PEMFileIdentity(pemFile: certificatePath)
    var configuration = TLSConfiguration(supportedVersions: supportedVersions, identity: identity)

    configuration.cipherSuites = cipherSuites
    //    configuration.identity = Identity(name: "Internet Widgits Pty Ltd")!
    if let dhParametersPath = dhParametersPath {
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
    }
    configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
    
    let server = TLSServerSocket(configuration: configuration)
    
    do {
        try server.listen(on: address)
    } catch (let error) {
        print("Error: \(error)")
    }
    
    while true {
        do {
            let clientSocket = try server.acceptConnection()
            print("New connection")
            while true {
                let data = try clientSocket.read(count: 1024)
                let string = String.fromUTF8Bytes(data)!
                print("Client Request:\n\(string)")
                if string.hasPrefix("GET ") {
                    let contentLength = string.utf8.count
                    let header = "HTTP/1.0 200 OK\r\nConnection: Close\r\nContent-Length: \(contentLength)\r\n\r\n"
                    let body = "\(string)"
                    try clientSocket.write(header + body)
                }
                //                try clientSocket.write(body)
                
                //            clientSocket.close()
            }
        }
        catch(let error) {
            if let tlserror = error as? TLSError {
                switch tlserror {
                case .error(let message):
                    print("Error: \(message)")
                case .alert(let alert, let level):
                    print("Alert: \(level) \(alert)")
                }
                
            }
            
            print("Error: \(error)")
            continue
        }
    }
}
