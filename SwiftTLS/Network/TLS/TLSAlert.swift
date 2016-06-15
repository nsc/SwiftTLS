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
    case warning = 1
    case fatal = 2
}

enum TLSAlert : UInt8
{
    case closeNotify = 0
    case unexpectedMessage = 10
    case badRecordMAC = 20
    case decryptionFailed = 21
    case recordOverflow = 22
    case decompressionFailure = 30
    case handshakeFailure = 40
    case noCertificate = 41 // SSLv3 only
    case badCertificate = 42
    case unsupportedCertificate = 43
    case certificateRevoked = 44
    case certificateExpired = 45
    case certificateUnknown = 46
    case illegalParameter = 47
    case unknownCA = 48
    case accessDenied = 49
    case decodeError = 50
    case decryptError = 51
    case exportRestriction = 60
    case protocolVersion = 70
    case insufficientSecurity = 71
    case internalError = 80
    case userCancelled = 90
    case noRenegotiation = 100
}

class TLSAlertMessage : TLSMessage
{
    let alertLevel : TLSAlertLevel
    let alert : TLSAlert
    
    init(alert: TLSAlert, alertLevel: TLSAlertLevel)
    {
        self.alertLevel = alertLevel
        self.alert = alert
        
        super.init(type: .alert(alertLevel, alert))
    }

    required init?(inputStream: InputStreamType, context: TLSContext)
    {
        if  let level : UInt8 = inputStream.read(),
            let alertLevel = TLSAlertLevel(rawValue: level),
            let rawAlert : UInt8 = inputStream.read(),
            let alert = TLSAlert(rawValue: rawAlert)
        {
            self.alertLevel = alertLevel
            self.alert = alert
        }
        else {
            return nil
        }
        
        super.init(type: .alert(self.alertLevel, self.alert))
    }

    override func writeTo<Target : OutputStreamType>(_ target: inout Target)
    {
        let data = [alertLevel.rawValue, alert.rawValue]
        target.write(data)
    }

    class func alertFromData(_ data : [UInt8], context: TLSContext) -> TLSAlertMessage?
    {
        return TLSAlertMessage(inputStream: BinaryInputStream(data), context: context)
    }
}
