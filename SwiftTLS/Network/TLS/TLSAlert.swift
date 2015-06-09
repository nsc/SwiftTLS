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

enum TLSAlert : UInt8
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

class TLSAlertMessage : TLSMessage
{
    let alertLevel : TLSAlertLevel
    let alert : TLSAlert
    
    init(alert: TLSAlert, alertLevel: TLSAlertLevel)
    {
        self.alertLevel = alertLevel
        self.alert = alert
        
        super.init(type: .Alert(alertLevel, alert))
    }

    required init?(inputStream: InputStreamType)
    {
        if  let level : UInt8 = read(inputStream),
            alertLevel = TLSAlertLevel(rawValue: level),
            let rawAlert : UInt8 = read(inputStream),
            alert = TLSAlert(rawValue: rawAlert)
        {
            self.alertLevel = alertLevel
            self.alert = alert
        }
        else {
            self.alertLevel = .Warning
            self.alert = .CloseNotify
        }
        
        super.init(type: .Alert(self.alertLevel, self.alert))
    }

    override func writeTo<Target : OutputStreamType>(inout target: Target)
    {
        let data = [alertLevel.rawValue, alert.rawValue]
        target.write(data)
    }

    class func alertFromData(data : [UInt8]) -> TLSAlertMessage?
    {
        return TLSAlertMessage(inputStream: BinaryInputStream(data: data))
    }
}