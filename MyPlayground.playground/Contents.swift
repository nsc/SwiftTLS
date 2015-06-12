//: Playground - noun: a place where people can play
//: Playground - noun: a place where people can play

func foo(var bytes : [UInt8]) -> Int
{
    return Int(Int(bytes[0]) << 16 + Int(bytes[1]) << 8 + Int(bytes[2]))
}

foo([1, 2, 3])

protocol KnowsLargerIntType : UnsignedIntegerType {
    typealias LargerIntType : UnsignedIntegerType
}

extension UInt8 : KnowsLargerIntType {
    typealias LargerIntType = UInt16
}

extension UInt16 : KnowsLargerIntType {
    typealias LargerIntType = UInt32
}

extension UInt32 : KnowsLargerIntType {
    typealias LargerIntType = UInt64
}

class BigInt<T : UnsignedIntegerType>
{
    var parts : [T]? = nil
}

func f<T : UnsignedIntegerType where T : KnowsLargerIntType>(a : BigInt<T>, _ b : BigInt<T>) -> BigInt<T>
{
    print("\(a.parts), \(b.parts)")
    
    return a
}

func g<T : UnsignedIntegerType where T : KnowsLargerIntType>(a : BigInt<T>)
{
    if T.self == UInt64.self {
        let b = BigInt<UInt32>()
        
        f(b, b)
    }
    
    f(a, a)
}

var a = BigInt<UInt8>()
a.parts = [1,2,3]

g(a)

var c : [UInt8] = []
while c.last != nil && c.last! != 0 {
    c.removeLast()
}




