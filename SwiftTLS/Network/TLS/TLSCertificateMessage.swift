//
//  TLSCertificateMessage.swift
//  Chat
//
//  Created by Nico Schmidt on 16.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import Security

class TLSCertificateMessage : TLSHandshakeMessage
{
    var certificates : [Certificate]
    
    var publicKey : CryptoKey? {
        get {
            if certificates.count < 1 {
                return nil
            }
            
            let certificate = certificates[0]
            println("\(certificate.commonName)")
            return certificate.publicKey
        }
    }
    
    init(certificates : [Certificate])
    {
        self.certificates = certificates
        
        super.init(type: .Handshake(.Certificate))
    }
    
    required init?(inputStream : InputStreamType)
    {
        var certificates : [Certificate]?
        
        let (type, bodyLength) = TLSHandshakeMessage.readHeader(inputStream)
        
        if let t = type {
            if t == TLSHandshakeType.Certificate {
                if let header : [UInt8] = read(inputStream, 3) {
                    var a = header[0]
                    var b = header[1]
                    var c = header[2]
                    var bytesForCertificates = Int(UInt32(a) << 16 + UInt32(b) << 8 + UInt32(c))
                    
                    certificates = []
                    
                    while bytesForCertificates > 0 {
                        if let certHeader : [UInt8] = read(inputStream, 3) {
                            var a = certHeader[0]
                            var b = certHeader[1]
                            var c = certHeader[2]
                            var bytesForCertificate = Int(UInt32(a) << 16 + UInt32(b) << 8 + UInt32(c))
                        
                            var data : [UInt8]? = read(inputStream, bytesForCertificate)
                            
                            if let d = data {
                                var certificate = Certificate(certificateData: d)
                                if let cert = certificate {
                                    certificates!.append(cert)
                                    println("common name: \(cert.commonName)")
                                }
                            }
                            
                            bytesForCertificate -= bytesForCertificate
                        }
                        else {
                            break
                        }
                    }
                }
            }
        }
        
        if  let certs = certificates
        {
            self.certificates = certs
            
            super.init(type: .Handshake(.Certificate))
        }
        else {
            self.certificates = []
            super.init(type: .Handshake(.Certificate))
            
            return nil
        }
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        var buffer = DataBuffer()
        
        for certificate in self.certificates {
            var certificateData = certificate.data
            writeUInt24(buffer, certificateData.count)
            write(buffer, certificateData)
        }
        
        var data = buffer.buffer

        let bodyLength = data.count + 3 // add 3 bytes for the 24 bit length of the certifacte data below
        self.writeHeader(type: .Certificate, bodyLength: bodyLength, target: &target)
        writeUInt24(target, data.count)
        write(target, data)
    }
}
