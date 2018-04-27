#!/usr/bin/env python

import sys

def extended_euclid(z, a):
    i = a
    j = z
    y1 = 1
    y2 = 0

    while j > 0:
        quotient  = i / j
        remainder = i % j

        print "quotient = %x" % quotient
        print "remainder = %x" % remainder

        y = y2 - y1 * quotient

        print "y = %x" % y

        i = j
        j = remainder
        y2 = y1
        y1 = y

    print "y2 = %x" % y2
    print "a = %x" % a

    result = y2 % a

    print "y2 %% a = %x" % result

    return result

def modular_inverse(x, y, mod):
    
    inverse = extended_euclid(y, mod)

    print "inverse = %x" % inverse

    result = (inverse * x) % mod

    print "result = %x" % result

    if result < 0:
        result = result + mod

    return result

x   = int(sys.argv[1], 16)
y   = int(sys.argv[2], 16)
mod = int(sys.argv[3], 16)

result = modular_inverse(x, y, mod)

print "%X" % result

print "check: (y * result) %% mod == %X" % ((y * result) % mod)
print "                             %X" % (x % mod)
