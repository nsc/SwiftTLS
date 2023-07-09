//
//  Log.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 22.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

class LoggingDateFormatter : DateFormatter
{
    override init()
    {
        super.init()
        dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    }
    
    required init?(coder aDecoder: NSCoder) {
        super.init(coder: aDecoder)
    }
}

public class Log
{
    @TaskLocal static var connectionNumber: Int?
    public static func withConnectionNumber<R>(_ n: Int, _ handler: () async throws -> R) async rethrows -> R {
        try await $connectionNumber.withValue(n) {
            try await handler()
        }
    }

    var enabled: Bool = true
    fileprivate let formatter = LoggingDateFormatter()
    private let logFile: FileHandle = FileHandle(fileDescriptor: 1)
    private let logQueue = DispatchQueue(label: "org.swifttls.logging")
    
    func log(_ message: @autoclosure () -> String, file: StaticString, line: UInt, prefixString: String = "") {
        if enabled {
            logQueue.sync {
                let line = "\(prefixString)\(message())\n"
                let utf8 = Data(line.utf8)

                logFile.write(utf8)
            }
        }
    }
}

private let logger = Log()
public func log(_ message: @autoclosure () -> String, file: StaticString = #file, line: UInt = #line) {
    var prefixString = "\(logger.formatter.string(from: Date())) "
    if let n = Log.connectionNumber {
        prefixString += "~\(n): "
    }

    logger.log(message(), file: file, line: line, prefixString: prefixString)
}

public func TLSEnableLogging(_ v: Bool) {
    logger.enabled = v
}
