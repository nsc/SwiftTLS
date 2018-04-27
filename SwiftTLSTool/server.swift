//
//  server.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation
import SwiftTLS

func parseHTTPHeader(_ string: String) -> [String:String] {
    var header: [String:String] = [:]
    for line in string.split(separator: "\r\n") {
        if line.starts(with: "GET") || line.starts(with: "POST") {
            continue
        }
        
        if let colon = line.index(of: ":") {
            let key = line[..<colon]
            let afterColon = line.index(after: colon)
            let value = line[afterColon...].trimmingCharacters(in: .whitespaces)
            
            header[String(key)] = String(value)
        }
    }
    
    return header
}

func server(address: IPAddress, certificatePath: String, dhParametersPath : String? = nil, cipherSuite: CipherSuite? = nil)
{    
    log("Listening on port \(address.port)")
    
    let supportedVersions: [TLSProtocolVersion] = [.v1_3, .v1_2]
    
    var cipherSuites : [CipherSuite] = [
//        .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        //        .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    ]
    
    if supportedVersions.contains(.v1_2) {
        cipherSuites.append(contentsOf: [
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
//            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
//            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
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
    if let dhParametersPath = dhParametersPath {
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
    }
    configuration.ecdhParameters = ECDiffieHellmanParameters(namedCurve: .secp256r1)
    
    let server = TLSServerSocket(configuration: configuration)
    
    do {
        try server.listen(on: address)
    } catch (let error) {
        log("Error: server.listen: \(error)")
    }
    
    while true {
        do {
            try server.acceptConnection(withEarlyDataResponseHandler: nil) { result in
                var clientSocket: TLSSocket
                switch result {
                case .client(let socket):
                    clientSocket = socket
                    
                case.error(let error):
                    log("Error accepting connection: \(error)")
                    return
                }

                while true {
                    do {
                        let data = try clientSocket.read(count: 4096)
                        let clientRequest = String.fromUTF8Bytes(data)!
                        let response = """
                        Date: \(Date())
                        \(clientSocket.connectionInfo)
                        
                        Your Request:
                        \(clientRequest)
                        """
                        
                        log("""
                            \(clientSocket.connectionInfo)
                            
                            Client Request:
                            \(clientRequest)
                            """)
                        
                        if clientRequest.hasPrefix("GET ") {
                            let httpHeader = parseHTTPHeader(clientRequest)
                            
                            let clientWantsMeToCloseTheConnection = (httpHeader["Connection"]?.lowercased() == "close")
                            
                            let contentLength = response.utf8.count
                            let header = "HTTP/1.0 200 OK\r\nConnection: Close\r\nContent-Length: \(contentLength)\r\n\r\n"
                            let body = "\(response)"
                            try clientSocket.write(header + body)
                            
                            if clientWantsMeToCloseTheConnection {
                                clientSocket.close()
                                break
                            }
                        }
                        //                try clientSocket.write(body)
                        
                        //            clientSocket.close()
                    } catch(let error) {
                        if let tlserror = error as? TLSError {
                            switch tlserror {
                            case .error(let message):
                                log("Error: \(message)")
                            case .alert(let alert, let level):
                                log("Alert: \(level) \(alert)")
                            }
                        }
                        
                        log("Error: \(error)")
                        break
                    }
                }
            }
        } catch (let error) {
            log("Error: \(error)")
        }
    }
}
