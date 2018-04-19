//
//  probeCipherSuites.swift
//  swifttls
//
//  Created by Nico Schmidt on 05.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

/*
import Foundation
import SwiftTLS

func probeCipherSuitesForHost(host : String, port : Int, protocolVersion: TLSProtocolVersion = .v1_2)
{
    class StateMachine : TLSClientStateMachine
    {
        internal var state: TLSState = .idle
        
        weak var socket : TLSSocket!
        var cipherSuite : CipherSuite!
        init(socket : TLSSocket)
        {
            self.socket = socket
        }
        
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
    
    for cipherSuite in CipherSuite.allValues {
        let socket = TLSClientSocket(supportedVersions: [protocolVersion])
        let stateMachine = StateMachine(socket: socket)
        socket.connection.stateMachine = stateMachine
        
        socket.connection.configuration.cipherSuites = [cipherSuite]
        
        do {
            stateMachine.cipherSuite = cipherSuite
            try socket.connect(address)
        } catch let error as SocketError {
            switch error {
            case .closed:
                socket.close()
                
            default:
                print("Error: \(error)")
            }
        }
        catch {
            //            print("Unhandled error: \(error)")
        }
    }
}
*/
