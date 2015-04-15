//: Playground - noun: a place where people can play

import Cocoa

var data = NSData(base64EncodedString: "ZMOP1NFa5VKTQ8I2awGXDjzKP+686eujiangAgf5N+Q=", options: NSDataBase64DecodingOptions(0))

var a = [UInt8](count: data!.length, repeatedValue: 0)
data?.getBytes(&a, length: a.count)
a
