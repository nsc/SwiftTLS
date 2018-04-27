//
//  TLSSocket.swift
//
//  Created by Nico Schmidt on 12.03.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

enum TLSSocketError : Error {
    case error
}

protocol OutputStreamType
{
    mutating func write(_ data : [UInt8])
}

protocol InputStreamType
{
    var bytesRead: Int {get set}
    func read(count : Int) -> [UInt8]?
}

protocol Streamable
{
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?)
}

extension OutputStreamType
{
    private mutating func write(_ data : [UInt16]) {
        for a in data {
            self.write([UInt8(a >> 8), UInt8(a & 0xff)])
        }
    }

    mutating func write8(_ data: [UInt8]) {
        self.write(UInt8(data.count))
        self.write(data)
    }

    mutating func write16(_ data: [UInt8]) {
        self.write(UInt16(data.count))
        self.write(data)
    }

    mutating func write16(_ data: [UInt16]) {
        self.write(UInt16(data.count * MemoryLayout<UInt16>.size))
        self.write(data)
    }

    mutating func write24(_ data: [UInt8]) {
        self.writeUInt24(data.count)
        self.write(data)
    }

    mutating func write(_ data : UInt8) {
        self.write([data])
    }
    
    mutating func write(_ data : UInt16) {
        self.write([UInt8(data >> 8), UInt8(data & 0xff)])
    }
    
    mutating func write(_ data : UInt32) {
        self.write([UInt8((data >> 24) & 0xff), UInt8((data >> 16) & 0xff), UInt8((data >>  8) & 0xff), UInt8((data >>  0) & 0xff)])
    }
    
    mutating func write(_ data : UInt64) {
        let a = UInt8((data >> 56) & 0xff)
        let b = UInt8((data >> 48) & 0xff)
        let c = UInt8((data >> 40) & 0xff)
        let d = UInt8((data >> 32) & 0xff)
        let e = UInt8((data >> 24) & 0xff)
        let f = UInt8((data >> 16) & 0xff)
        let g = UInt8((data >>  8) & 0xff)
        let h = UInt8((data >>  0) & 0xff)

        self.write([a, b, c, d, e, f, g, h])
    }
    
    mutating func writeUInt24(_ value : Int)
    {
        self.write([UInt8((value >> 16) & 0xff), UInt8((value >>  8) & 0xff), UInt8((value >>  0) & 0xff)])
    }
    
    mutating func write<T: Streamable>(_ data: T) {
        data.writeTo(&self, context: nil)
    }
}

extension InputStreamType
{
    func read() -> UInt8?
    {
        if let a : [UInt8] = self.read(count: 1) {
            return a[0]
        }
        
        return nil
    }
    
    func read() -> UInt16?
    {
        if let s : [UInt8] = self.read(count: 2) {
            return UInt16(s[0]) << 8 + UInt16(s[1])
        }
        
        return nil
    }
    
    func read() -> UInt32?
    {
        if let s : [UInt8] = self.read(count: 4) {
            
            let a = UInt32(s[0])
            let b = UInt32(s[1])
            let c = UInt32(s[2])
            let d = UInt32(s[3])
            
            return a << 24 + b << 16 + c << 8 + d
        }
        
        return nil
    }
    
    func read(count: Int) -> [UInt16]?
    {
        if let s : [UInt8] = self.read(count: count * 2) {
            var buffer = [UInt16](repeating: 0, count: count)
            for i in 0 ..< count {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }
    
    func read(bytes: Int) -> [UInt16]?
    {
        let count = bytes / 2
        if let s : [UInt8] = self.read(count: bytes) {
            var buffer = [UInt16](repeating: 0, count: count)
            for i in 0 ..< count {
                buffer[i] = UInt16(s[2 * i]) << 8 + UInt16(s[2 * i + 1])
            }
            
            return buffer
        }
        
        return nil
    }

    func readUInt24() -> Int?
    {
        if  let a : [UInt8] = self.read(count: 3)
        {
            return Int(a[0]) << 16 + Int(a[1]) << 8 + Int(a[2])
        }
        
        return nil
    }
    
    func read8() -> [UInt8]?
    {
        guard
            let count : UInt8 = self.read(),
            let data : [UInt8] = self.read(count: Int(count))
            else {
                return nil
        }
        
        return data
    }

    func read16() -> [UInt8]?
    {
        guard
            let count : UInt16 = self.read(),
            let data : [UInt8] = self.read(count: Int(count))
        else {
            return nil
        }
        
        return data
    }

    func read8() -> [UInt16]?
    {
        guard
            let count : UInt8 = self.read(),
            let data : [UInt16] = self.read(count: Int(count) / MemoryLayout<UInt16>.size)
            else {
                return nil
        }
        
        return data
    }

    func read16() -> [UInt16]?
    {
        guard
            let count : UInt16 = self.read(),
            let data : [UInt16] = self.read(bytes: Int(count))
            else {
                return nil
        }
        
        return data
    }

}

class Random : Streamable, Equatable
{
    static let NumberOfRandomBytes = 28
    var gmtUnixTime : UInt32
    var randomBytes : [UInt8]
    
    var bytes: [UInt8] {
        return self.gmtUnixTime.bigEndianBytes + randomBytes
    }
    
    init()
    {
        randomBytes = TLSRandomBytes(count: 28)
        
        gmtUnixTime = UInt32(Date().timeIntervalSinceReferenceDate)
    }
    
    init?(_ bytes: [UInt8])
    {
        guard bytes.count == 32 else {
            return nil
        }
        
        self.gmtUnixTime = UInt32(bigEndianBytes: bytes[0..<4])!
        self.randomBytes = [UInt8](bytes[4..<32])
    }
    
    required init?(inputStream : InputStreamType)
    {
        if  let time : UInt32 = inputStream.read(),
            let bytes : [UInt8] = inputStream.read(count: Random.NumberOfRandomBytes)
        {
            self.gmtUnixTime = time
            self.randomBytes = bytes
        }
        else {
            return nil
        }
    }
    
    func writeTo<Target : OutputStreamType>(_ target: inout Target, context: TLSConnection?) {
        target.write(gmtUnixTime)
        target.write(randomBytes)
    }
    
    static func == (lhs: Random, rhs: Random) -> Bool {
        return lhs.gmtUnixTime == rhs.gmtUnixTime && lhs.randomBytes == rhs.randomBytes
    }
}

extension Socket : TLSDataProvider
{
    func readData(count: Int) throws -> [UInt8] {
        return try self.read(count: count)
    }
    
    func writeData(_ data: [UInt8]) throws {
        try self.write(data)
    }
}

public class TLSSocket : SocketProtocol, TLSDataProvider
{
    var connection : TLSConnection! {
        didSet {
            connection.recordLayer = TLS1_3.RecordLayer(connection: connection, dataProvider: self.socket)
        }
    }
    
    public var connectionInfo: String {
        return """
        TLS Version: \(self.negotiatedProtocolVersion!)
        Cipher: \(self.cipherSuite!)
        \(connection.info)
        """
    }
    
    public var cipherSuite: CipherSuite? {
        return self.connection?.cipherSuite
    }
    
    public var negotiatedProtocolVersion: TLSProtocolVersion? {
        return self.connection?.negotiatedProtocolVersion
    }

    var socket : TCPSocket!
    
    public init(connection: TLSConnection)
    {
        self.socket = TCPSocket()
        self.connection = connection
        connection.recordLayer = TLS1_3.RecordLayer(connection: connection, dataProvider: self.socket)
    }
    
    public func close()
    {
        do {
            try self.connection.sendAlert(.closeNotify, alertLevel: .warning)
        }
        catch
        {
        }
        
        // When the send is done, close the underlying socket
        // We might want to have an option to wait for the peer to send *its* closeNotify if it wants to
        self.socket?.close()
    }
    
    public func read(count: Int) throws -> [UInt8]
    {
        let message = try self.connection.readTLSMessage()
        switch message.type
        {
        case .applicationData:
            let applicationData = (message as! TLSApplicationData).applicationData
            
            if applicationData.count == 0 {
                return try self.read(count: count)
            }
            else {
                return applicationData
            }
            
        case .alert(let level, let alert):
            log("Alert: \(level) \(alert)")
            return []
            
        default:
            throw TLSError.error("Error: unhandled message \(message)")
        }
    }

    func readData(count: Int) throws -> [UInt8]
    {
        return try self.socket!.read(count: count)
    }
    
    func writeData(_ data: [UInt8]) throws
    {
        try self.socket?.write(data)
    }
    
    public func write(_ data: [UInt8]) throws
    {
        try self.connection.sendApplicationData(data)
    }
}

public class TLSClientSocket : TLSSocket, ClientSocketProtocol
{
    public var context: TLSContext {
        return self.client.context
    }
    
    private var client: TLSClient {
        return self.connection as! TLSClient
    }
    
    private var earlyData: Data?
    
    convenience public init(supportedVersions: [TLSProtocolVersion])
    {
        self.init(configuration: TLSConfiguration(supportedVersions: supportedVersions))
    }
    
    public init(configuration: TLSConfiguration, context: TLSClientContext? = nil)
    {
        super.init(connection: TLSClient(configuration: configuration, context: context))
    }

    public func connect(_ address: IPAddress, withEarlyData earlyData: Data) throws
    {
        self.earlyData = earlyData
        try self.socket?.connect(address)
        try self.client.startConnection(withEarlyData: self.earlyData)
    }

    // Connect with early data. If the early data could actually be sent, returns true, fals otherwise
    public func connect(hostname: String, port: UInt16 = 443, withEarlyData earlyData: Data) throws -> Bool
    {
        self.earlyData = earlyData
        
        try connect(hostname: hostname, port: port)
        
        return self.client.earlyDataWasSent
    }

    public func connect(hostname: String, port: UInt16 = 443) throws
    {
        if let address = IPAddress.addressWithString(hostname, port: port) {
            var hostNameAndPort = hostname
            if port != 443 {
                hostNameAndPort = "\(hostname):\(port)"
            }
            self.connection.serverNames = [hostNameAndPort]
            
            try connect(address)
        }
        else {
            throw TLSError.error("Error: Could not resolve host \(hostname)")
        }
        
    }
    
    // TODO: add connect method that takes a domain name rather than an IP
    // so we can check the server certificate against that name
    public func connect(_ address: IPAddress) throws
    {
        try self.socket?.connect(address)
        try self.client.startConnection(withEarlyData: self.earlyData)
    }
    
//    public func renegotiate() throws
//    {
//        try self.client.renegotiate()
//    }
}

public class TLSServerSocket : TLSSocket, ServerSocketProtocol
{
    private var server: TLSServer {
        return self.connection as! TLSServer
    }

    var context: TLSContext {
        return self.server.context
    }

    convenience public init(supportedVersions: [TLSProtocolVersion])
    {
        self.init(configuration: TLSConfiguration(supportedVersions: supportedVersions))
    }
    
    public init(configuration: TLSConfiguration)
    {
        super.init(connection: TLSServer(configuration: configuration))
    }

    public func listen(on address: IPAddress) throws {
        try self.socket?.listen(on: address)
    }

    public func acceptConnection() throws -> SocketProtocol {
        return try acceptConnection(withEarlyDataResponseHandler: nil)
    }

    public typealias EarlyDataResponseHandler = ((_ earlyData: Data) -> (Data?))
    
    /// Accept a connection
    ///
    /// - Parameter earlyDataResponseHandler: if the client sends early data and the server is configured
    ///                                       to accept it, the earlyDataResponseHandler is called with the early data
    ///                                       and it can return a response that is send with the first flight
    ///
    /// - Returns: the socket rerpresenting the client that has connected
    /// - Throws: Mainly TLSError I think :) (Make this more rigorous)
    public func acceptConnection(withEarlyDataResponseHandler earlyDataResponseHandler: EarlyDataResponseHandler?) throws -> SocketProtocol
    {
        let clientSocket = try self.socket?.acceptConnection() as! TCPSocket
        
        let clientTLSSocket = TLSServerSocket(supportedVersions: self.connection.configuration.supportedVersions)
        clientTLSSocket.socket = clientSocket
        clientTLSSocket.connection.signer = self.connection.signer
        clientTLSSocket.connection.configuration = self.connection.configuration
        clientTLSSocket.connection.recordLayer.dataProvider = clientTLSSocket
        clientTLSSocket.connection.context = self.context
        
        clientTLSSocket.server.earlyDataResponseHandler = earlyDataResponseHandler
        
        try clientTLSSocket.server.acceptConnection()
        
        return clientTLSSocket
    }
    
    public enum AcceptConnectionResult
    {
        case error(Error)
        case client(TLSSocket)
    }

    public func acceptConnection(withEarlyDataResponseHandler earlyDataResponseHandler: EarlyDataResponseHandler?, completionHandler: @escaping (AcceptConnectionResult) -> ()) throws
    {
        let clientSocket = try self.socket?.acceptConnection() as! TCPSocket
        
        let queue = DispatchQueue.global()

        queue.async {
            
            let clientTLSSocket = TLSServerSocket(supportedVersions: self.connection.configuration.supportedVersions)
            clientTLSSocket.socket = clientSocket
            clientTLSSocket.connection.signer = self.connection.signer
            clientTLSSocket.connection.configuration = self.connection.configuration
            clientTLSSocket.connection.recordLayer.dataProvider = clientTLSSocket
            clientTLSSocket.connection.context = self.context
            
            clientTLSSocket.server.earlyDataResponseHandler = earlyDataResponseHandler
         
            do {
                try clientTLSSocket.server.acceptConnection()
            } catch let error {
                completionHandler(.error(error))
            }
            
            completionHandler(.client(clientTLSSocket))
            
            Thread.current.removeThreadNumber()
        }
    }


}
