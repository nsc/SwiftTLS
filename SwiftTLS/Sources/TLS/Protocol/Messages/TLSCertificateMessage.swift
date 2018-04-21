//
//  TLSCertificateMessage.swift
//
//  Created by Nico Schmidt on 16.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

class TLSCertificateMessage : TLSHandshakeMessage
{
    var certificateRequestContext: [UInt8]? // TLS 1.3
    var certificates : [X509.Certificate]
    
    init(certificates : [X509.Certificate])
    {
        self.certificates = certificates
        
        super.init(type: .handshake(.certificate))
    }
    
    required init?(inputStream : InputStreamType, context: TLSConnection)
    {
        var certificates : [X509.Certificate]?
        
        guard let (type, _) = TLSHandshakeMessage.readHeader(inputStream), type == TLSHandshakeType.certificate
        else {
            return nil
        }
        
        if context.negotiatedProtocolVersion! >= .v1_3 {
            certificateRequestContext = inputStream.read8()
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
                        
                        if let cert = x509Cert {
                            certificates!.append(cert)
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

    override func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
    {
        guard let context = context else {
            fatalError()
        }

        var certificateData: [UInt8] = []

        if context.negotiatedProtocolVersion! >= .v1_3 {
            let certificateRequestContext = self.certificateRequestContext ?? []
            certificateData.write8(certificateRequestContext)
        }
        
        var certificatesList: [UInt8] = []
        for certificate in self.certificates {
            let certificateData = certificate.data
            certificatesList.writeUInt24(certificateData.count)
            certificatesList.write(certificateData)
            
            if context.negotiatedProtocolVersion! >= .v1_3 {
                let extensions: [TLSExtension] = []
                TLSWriteExtensions(&certificatesList, extensions: extensions, messageType: .certificate, context: context)
            }
        }
        certificateData.write24(certificatesList)

        let bodyLength = certificateData.count
        self.writeHeader(type: .certificate, bodyLength: bodyLength, target: &target)
        target.write(certificateData)
    }
}
