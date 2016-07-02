//
//  TLSCertificateMessage.swift
//
//  Created by Nico Schmidt on 16.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation
import Security

class TLSCertificateMessage : TLSHandshakeMessage
{
    var certificates : [X509.Certificate]
    
    init(certificates : [X509.Certificate])
    {
        self.certificates = certificates
        
        super.init(type: .handshake(.certificate))
    }
    
    required init?(inputStream : InputStreamType, context: TLSContext)
    {
        var certificates : [X509.Certificate]?
        
        guard let (type, _) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.certificate
        else {
            return nil
        }
        
        if let header : [UInt8] = inputStream.read(count: 3) {
            let a = UInt32(header[0])
            let b = UInt32(header[1])
            let c = UInt32(header[2])
            let bytesForCertificates = Int(a << 16 + b << 8 + c)
            
            certificates = []
            
            while bytesForCertificates > 0 {
                if let certHeader : [UInt8] = inputStream.read(count: 3) {
                    let a = UInt32(certHeader[0])
                    let b = UInt32(certHeader[1])
                    let c = UInt32(certHeader[2])
                    var bytesForCertificate = Int(a << 16 + b << 8 + c)
                    
                    let data : [UInt8]? = inputStream.read(count: bytesForCertificate)
                    
                    if let d = data {
                        let x509Cert = X509.Certificate(derData: d)
                        print(x509Cert)
                        
                        if let cert = x509Cert {
                            certificates!.append(cert)
                            print("common name: \(cert.commonName)")
                        }
                    }
                    
                    bytesForCertificate -= bytesForCertificate
                }
                else {
                    break
                }
            }
        }
    
        if  let certs = certificates
        {
            self.certificates = certs
            
            super.init(type: .handshake(.certificate))
        }
        else
        {
            return nil
        }
    }

    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        let buffer = DataBuffer()
        
        for certificate in self.certificates {
            let certificateData = certificate.data
            buffer.writeUInt24(certificateData.count)
            buffer.write(certificateData)
        }
        
        let data = buffer.buffer

        let bodyLength = data.count + 3 // add 3 bytes for the 24 bit length of the certifacte data below
        self.writeHeader(type: .certificate, bodyLength: bodyLength, target: &target)
        target.writeUInt24(data.count)
        target.write(data)
    }
}
