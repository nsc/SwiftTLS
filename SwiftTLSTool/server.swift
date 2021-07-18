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
        
        if let colon = line.firstIndex(of: ":") {
            let key = line[..<colon]
            let afterColon = line.index(after: colon)
            let value = line[afterColon...].trimmingCharacters(in: .whitespaces)
            
            header[String(key)] = String(value)
        }
    }
    
    return header
}

func server(address: IPAddress = IPv6Address.anyAddress, certificatePath: String, dhParametersPath : String? = nil, cipherSuite: CipherSuite? = nil, supportedVersions: [TLSProtocolVersion]? = nil) async
{    
    log("Listening on port \(address.port)")
    
    let identity = PEMFileIdentity(pemFile: certificatePath)
    var configuration: TLSConfiguration
    if let cipherSuite = cipherSuite {
        configuration = TLSConfiguration(supportedVersions: cipherSuite.descriptor!.supportedProtocolVersions, identity: identity)
        configuration.cipherSuites = [cipherSuite]
    }
    else if let supportedVersions = supportedVersions {
        configuration = TLSConfiguration(supportedVersions: supportedVersions, identity: identity)
    }
    else {
        configuration = TLSConfiguration(identity: identity)
    }
    
    configuration.earlyData = .supported(maximumEarlyDataSize: 40960)
    
    if let dhParametersPath = dhParametersPath {
        configuration.dhParameters = DiffieHellmanParameters.fromPEMFile(dhParametersPath)
    }
    
    configuration.supportedGroups = [.secp256r1, .secp384r1, .secp521r1]
    
    let server = TLSServer(configuration: configuration)
    
    do {
        try server.listen(on: address)
    } catch (let error) {
        log("Error: server.listen: \(error)")
    }
    
    while true {
        do {
            try await server.acceptConnection(withEarlyDataResponseHandler: responder(connection:data:)) { result in
                var client: TLSConnection
                switch result {
                case .client(let connection):
                    client = connection
                    
                case.error(let error):
                    log("Error accepting connection: \(error)")
                    return
                }
                
                var earlyData = client.earlyData
                while true {
                    do {
                        let data: [UInt8]
                        if earlyData != nil {
                            data = earlyData!
                            earlyData = nil
                        }
                        else {
                            data = try await client.read(count: 4096)
                        }
                        
                        if let response = await responder(connection: client, data: Data(data)) {
                            try await client.write(response)
                            
                            print("Sending response:\n \(response)")
                            
                            if clientWantsMeToCloseTheConnection {
                                await client.close()
                                break
                            }
                        }
                    } catch(let error) {
                        if let tlserror = error as? TLSError {
                            switch tlserror {
                            case .error(let message):
                                log("Error: \(message)")
                            case .alert(let alert, let level, let message):
                                log("Alert: \(level) \(alert)\(message != nil ? ": " + message! : "")")
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

var clientWantsMeToCloseTheConnection = false
func responder(connection: TLSConnection, data: Data) async -> Data? {
    let utf8Data = String(data: data, encoding: .utf8)
    let clientRequest: String
    if let utf8Data = utf8Data {
        clientRequest = utf8Data
    }
    else {
        clientRequest = data.reduce("", { $0 + String(format: "%02x ", $1)})
    }

    let response = """
    <!DOCTYPE html>
    <html lang="en">
    <title>Swift TLS</title>
    <meta charset="utf-8">
    <body>
    <pre>
    Date: \(Date())
    \(connection.connectionInfo)
    
    Your Request:
    \(clientRequest)
    
    </pre>
    <a href="/">reload</a>
    </body></html>
    """
    
    log("""
        \(connection.connectionInfo)
        
        Client Request:
        \(clientRequest)
        """)
    
    if clientRequest.hasPrefix("GET ") {
        let httpHeader = parseHTTPHeader(clientRequest)
        
        clientWantsMeToCloseTheConnection = (httpHeader["Connection"]?.lowercased() == "close")
        
        let contentLength = response.utf8.count
        let header = """
            HTTP/1.1 200 OK
            Server: SwiftTLS
            Strict-Transport-Security: max-age=63072000
            Connection: Close
            Content-Type: text/html
            Content-Length: \(contentLength)
            """
            .replacingOccurrences(of: "\n", with: "\r\n")
            + "\r\n\r\n"
        
        let body = "\(response)"
        
        let responseData = (header + body).data(using: .utf8)

        return responseData
    }
    
    return nil
}

