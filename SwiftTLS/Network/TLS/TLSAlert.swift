//
//  TLSAlert.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 26.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSAlertLevel : UInt8
{
    case Warning = 1
    case Fatal = 2
}

enum TLSAlertDescription : UInt8
{
    case CloseNotify = 0
    case UnexpectedMessage = 10
    case BadRecordMAC = 20
    case DecryptionFailed = 21
    case RecordOverflow = 22
    case DecompressionFailure = 30
    case HandshakeFailure = 40
    case NoCertificate = 41 // SSLv3 only
    case BadCertificate = 42
    case UnsupportedCertificate = 43
    case CertificateRevoked = 44
    case CertificateExpired = 45
    case CertificateUnknown = 46
    case IllegalParameter = 47
    case UnknownCA = 48
    case AccessDenied = 49
    case DecodeError = 50
    case DecryptError = 51
    case ExportRestriction = 60
    case ProtocolVersion = 70
    case InsufficientSecurity = 71
    case InternalError = 80
    case UserCancelled = 90
    case NoRenegotiation = 100
}

class TLSAlert : TLSMessage
{
    let alertLevel : TLSAlertLevel
    let alertDescription : TLSAlertDescription
    
    init(alertLevel: TLSAlertLevel, alertDescription: TLSAlertDescription)
    {
        self.alertLevel = alertLevel
        self.alertDescription = alertDescription
        
        super.init(type: .Alert(alertLevel, alertDescription))
    }

    required init?(inputStream: BinaryInputStreamType)
    {
        if  let level : UInt8 = inputStream.read(),
            alertLevel = TLSAlertLevel(rawValue: level),
            let description : UInt8 = inputStream.read(),
            alertDescription = TLSAlertDescription(rawValue: description)
        {
            self.alertLevel = alertLevel
            self.alertDescription = alertDescription
        }
        else {
            self.alertLevel = .Warning
            self.alertDescription = .CloseNotify
        }
        
        super.init(type: .Alert(self.alertLevel, self.alertDescription))
    }

    class func alertFromData(data : [UInt8]) -> TLSAlert?
    {
        return TLSAlert(inputStream: BinaryInputStream(data: data))
    }
}