//
//  scan.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

func scan()
{
    class StateMachine : TLSClientStateMachine
    {
        internal var state: TLSState = .idle
        
        var shouldStopHandshake: Bool = false
        
        weak var socket : TLSSocket!
        init(socket : TLSSocket)
        {
            self.socket = socket
        }
        
        func shouldContinueHandshake(with message: TLSHandshakeMessage) -> Bool
        {
            return !shouldStopHandshake
        }

        func didReceiveHandshakeMessage(_ message: TLSHandshakeMessage) throws {
            guard let certificate = message as? TLSCertificateMessage else {
                return
            }
            
            for certificate in certificate.certificates {
                print("-----BEGIN CERTIFICATE-----")
                print(Data(bytes: certificate.data).base64EncodedString())
                print("-----END CERTIFICATE-----")
            }
        }
        
        func didReceiveAlert(_ alert: TLSAlertMessage) {
        }
    }
    
//    let address = IPAddress.addressWithString("www.google.com", port: 443)!
    
    let socket = TLSClientSocket(supportedVersions: [.v1_2])
    let stateMachine = StateMachine(socket: socket)
    socket.connection.stateMachine = stateMachine
    
    socket.connection.configuration.cipherSuites = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
    
    do {
        try socket.connect(hostname: "www.google.com")
    } catch let error as SocketError {
        switch error {
        case .closed:
            socket.close()
            
        default:
            print("Error: \(error)")
        }
    }
    catch {
        print("Unhandled error: \(error)")
    }

}
