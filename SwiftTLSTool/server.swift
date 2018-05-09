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

func server(address: IPAddress, certificatePath: String, dhParametersPath : String? = nil, cipherSuite: CipherSuite? = nil, supportedVersions: [TLSProtocolVersion]? = nil)
{    
    log("Listening on port \(address.port)")
    
    let identity = PEMFileIdentity(pemFile: certificatePath)
    var configuration: TLSConfiguration
    if let supportedVersions = supportedVersions {
        configuration = TLSConfiguration(supportedVersions: supportedVersions, identity: identity)
    }
    else {
        configuration = TLSConfiguration(identity: identity)
    }
    
    if let cipherSuite = cipherSuite {
        configuration.cipherSuites = [cipherSuite]
    }
    
    if let dhParametersPath = dhParametersPath {
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
    }
    
    let server = TLSServer(configuration: configuration)
    
    do {
        try server.listen(on: address)
    } catch (let error) {
        log("Error: server.listen: \(error)")
    }
    
    while true {
        do {
            try server.acceptConnection(withEarlyDataResponseHandler: nil) { result in
                var client: TLSConnection
                switch result {
                case .client(let connection):
                    client = connection
                    
                case.error(let error):
                    log("Error accepting connection: \(error)")
                    return
                }

                while true {
                    do {
                        let data = try client.read(count: 4096)
                        let clientRequest = String.fromUTF8Bytes(data)!
                        let response = """
                        Date: \(Date())
                        \(client.connectionInfo)
                        
                        Your Request:
                        \(clientRequest)
                        """
                        
                        log("""
                            \(client.connectionInfo)
                            
                            Client Request:
                            \(clientRequest)
                            """)
                        
                        if clientRequest.hasPrefix("GET ") {
                            let httpHeader = parseHTTPHeader(clientRequest)
                            
                            let clientWantsMeToCloseTheConnection = (httpHeader["Connection"]?.lowercased() == "close")
                            
                            let contentLength = response.utf8.count
                            let header = "HTTP/1.0 200 OK\r\nServer: SwiftTLS\r\nConnection: Close\r\nContent-Length: \(contentLength)\r\n\r\n"
                            let body = "\(response)"
                            try client.write(header + body)
                            
                            if clientWantsMeToCloseTheConnection {
                                client.close()
                                break
                            }
                        }
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
