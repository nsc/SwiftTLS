//: Playground - noun: a place where people can play

import Cocoa

var data = NSData(base64EncodedString: "ZMOP1NFa5VKTQ8I2awGXDjzKP+686eujiangAgf5N+Q=", options: NSDataBase64DecodingOptions(0))

var a = [UInt8](count: data!.length, repeatedValue: 0)
data?.getBytes(&a, length: a.count)
a

func f(ints:Int...) -> String {
    return "\(ints)"
}

f(1,2,3,4)


class Base
{
    required init(a : Int)
    {
    }
}

class Derived : Base
{
}

var d = Derived(a:1)
let type = d.dynamicType
type(a: 2)


var n0 = UInt64(0x123456789abcdef0)
var n = n0 + n0


class A
{
    var a : Int64
    
    init(_ a : Int64)
    {
        self.a = a
    }
    
    init<T where T : IntegerType>(_ a : T)
    {
        self.a = a.toIntMax()
    }
}

func ==(lhs : A, rhs : A) -> Bool
{
    return lhs.a == rhs.a
}

A(1) == A(1)


var s = "0123456789abcdef"

for c in s.utf8 {
    c
}