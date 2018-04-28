//
//  probeCipherSuites.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//


import Foundation
import SwiftTLS

func probeCipherSuitesForHost(host : String, port : UInt16, protocolVersion: TLSProtocolVersion = .v1_3)
{
    class StateMachine : TLSClientStateMachine
    {
        internal var state: TLSState = .idle
        
        var cipherSuite : CipherSuite!
        
        func shouldContinueHandshake(with message: TLSHandshakeMessage) -> Bool
        {
            if let hello = message as? TLSServerHello {
                print("\(hello.cipherSuite)")
                
                return false
            }
            
            return true
        }
        
        func didReceiveAlert(_ alert: TLSAlertMessage) {
            //            print("\(cipherSuite) not supported")
            //            print("NO")
        }
    }
    
    guard let address = IPAddress.addressWithString(host, port: port) else { print("Error: No such host \(host)"); return }
    
    let cipherSuites = CipherSuite.allValues.filter({
        // TLS 1.3 cipher suites are currently only in the range 0x1300...0x1305
        if protocolVersion == .v1_3 {
            return ($0.rawValue & 0xff00) == 0x1300
        }
        
        return ($0.rawValue & 0xff00) != 0x1300
    })
    
    for cipherSuite in cipherSuites {
        let stateMachine = StateMachine()
        let client = TLSClient(configuration: TLSConfiguration(supportedVersions: [protocolVersion]), stateMachine: stateMachine)
        
        client.configuration.cipherSuites = [cipherSuite]
        
        do {
            stateMachine.cipherSuite = cipherSuite
            try client.connect(address)
        } catch let error as SocketError {
            switch error {
            case .closed:
                client.close()
                
            default:
                print("Error: \(error)")
            }
        }
        catch {
            //            print("Unhandled error: \(error)")
        }
    }
}

