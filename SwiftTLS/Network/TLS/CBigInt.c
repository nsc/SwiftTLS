//
//  CBigInt.c
//  SwiftTLS
//
//  Created by Nico Schmidt on 12.09.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "CBigInt.h"

static inline uint32_t max(uint32_t a, uint32_t b)
{
    return ((a > b) ? a : b);
}

static void normalize(CBigInt *a)
{
    if (a->count == 0) {
        return;
    }
    
    int count = a->count;
    for (int i = count - 1; i >= 0; --i)
    {
        if (a->parts[i] != 0)
            break;
        
        --count;
    }
    
    a->count = count;
}

static void CBigIntExtendCapacity(CBigInt *b, int capacity)
{
    if (capacity <= b->count) {
        return;
    }
    
    b->parts = realloc(b->parts, capacity * sizeof(uint32_t));
    b->capacity = capacity;
}

CBigInt *CBigIntCreateWithParts(uint32_t *parts, uint32_t count)
{
    CBigInt *bigInt = malloc(sizeof(CBigInt));
    uint32_t *newParts = malloc(count * sizeof(uint32_t));
    memcpy(newParts, parts, count * sizeof(uint32_t));
    
    bigInt->count = count;
    bigInt->sign = 0;
    bigInt->capacity = count;
    bigInt->parts = newParts;
    
    return bigInt;
}

CBigInt *CBigIntCreateWithCapacity(uint32_t count)
{
    CBigInt *bigInt = malloc(sizeof(CBigInt));
    uint32_t *newParts = malloc(count * sizeof(uint32_t));
    memset(newParts, 0, count * sizeof(uint32_t));
    
    bigInt->count = 0;
    bigInt->sign = 0;
    bigInt->capacity = count;
    bigInt->parts = newParts;
    
    return bigInt;
}

CBigInt *CBigIntCopyWithCapacity(CBigInt *b, int capacity)
{
    CBigInt *bigInt = malloc(sizeof(CBigInt));
    uint32_t *newParts = malloc(capacity * sizeof(uint32_t));
    memcpy(newParts, b->parts, b->count * sizeof(uint32_t));
    
    bigInt->count = b->count;
    bigInt->sign = b->sign;
    bigInt->capacity = capacity;
    bigInt->parts = newParts;
    
    return bigInt;
}

CBigInt *CBigIntCopy(CBigInt *b)
{
    return CBigIntCopyWithCapacity(b, b->count);
}

CBigInt *CBigIntCreateWithInt(int a)
{
    char sign = (a < 0);
    CBigInt *bigInt = CBigIntCreateWithCapacity(1);
    bigInt->count = 1;
    bigInt->parts[0] = abs(a);
    bigInt->sign = sign;
    
    return bigInt;
}

CBigInt *CBigIntCreateWithHexString(const char *hexString)
{
    size_t length = strlen(hexString);
    
    CBigInt *result = CBigIntCreateWithCapacity((uint32_t)(length + 7) / 8);
    
    uint32_t v = 0;
    int index = 0;
    int firstPartLength = length % 8;
    for (size_t i = 0; i < length; ++i)
    {
        const char c = hexString[i];
        uint8_t a;
        if (c >= '0' && c <= '9') {
            a = c - 0x30;
        }
        else if (c >= 'A' && c <= 'F') {
            a = c - 'A' + 0xa;
        }
        else if (c >= 'a' && c <= 'f') {
            a = c - 'a' + 0xa;
        }
        else {
            CBigIntFree(result);
            
            return NULL;
        }
        
        v = (v << 4) + a;

        if (i == firstPartLength - 1 || ((i > firstPartLength) && (i - firstPartLength) % 8 == 7)) {
            result->parts[index] = v;
            ++index;
            
            v = 0;
        }
    }
    
    if (v != 0) {
        result->parts[index] = v;
        result->count = index + 1;
    }
    else {
        result->count = index;
    }
    
    // reverse parts
    for (int i = 0; i < (index + 1)/2; ++i)
    {
        uint32_t tmp = result->parts[i];
        result->parts[i] = result->parts[result->count - 1 - i];
        result->parts[result->count - 1 - i] = tmp;
    }
    
    return result;
}

void CBigIntFree(CBigInt *b)
{
    free(b->parts);
    free(b);
}


static char hexDigit(uint8_t v)
{
    switch (v)
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
            return '0' + v;
            
        case 0xa:
        case 0xb:
        case 0xc:
        case 0xd:
        case 0xe:
        case 0xf:
            return 'A' + (v - 0xa);
    }
        
    return 0;
}

const char *CBigIntHexString(const CBigInt *b)
{
    int count = b->count;
    int length = count * 8;
    char *s = malloc(length + 1);
    
    char onlyZeroesYet = 1;
    int index = 0;
    for (int i = count - 1; i >= 0; --i)
    {
        uint32_t part = b->parts[i];
        uint8_t c;
        
        uint32_t shift = (sizeof(uint32_t) - 1) * 8;
        uint32_t mask  = 0xff << shift;
        for (int j = 0; j < sizeof(uint32_t); ++j)
        {
            c = (part & mask) >> shift;
            if (!onlyZeroesYet || c != 0) {
                
                char digit;
                digit = hexDigit(c >> 4);
                s[index] = digit;
                ++index;
                
                digit = hexDigit(c & 0xf);
                s[index] = digit;
                ++index;

                onlyZeroesYet = 0;
            }
            
            mask = mask >> 8;
            shift = shift - 8;
        }
    }
    
    if (onlyZeroesYet) {
        s[0] = '0';
        s[1] = 0;
        
        return s;
    }
    else {
        s[index] = 0;
    }
    
    return s;

}

void CBigIntHexStringFree(const char *p)
{
    free((void *)p);
}

CBigInt *CBigIntAdd(CBigInt *a, CBigInt *b)
{
    if (a->sign != b->sign) {
        if (a->sign) {
            CBigInt a1;
            a1.sign = 0;
            a1.parts = a->parts;
            a1.count = a->count;
            
            return CBigIntSubtract(b, &a1);
        }
        else {
            CBigInt b1;
            b1.sign = 0;
            b1.parts = b->parts;
            b1.count = b->count;

            return CBigIntSubtract(a, &b1);
        }
    }
    
    uint32_t count = max(a->count, b->count);
    CBigInt *result = CBigIntCreateWithCapacity(count + 1);
    
    result->sign = a->sign;
    
    uint32_t carry = 0;
    uint32_t i = 0;
    for (; i < count; ++i)
    {
        uint64_t sum = carry;
        carry = 0;
        
        if (i < a->count) {
            uint64_t tmp = sum + a->parts[i];
            char overflow = (tmp > UINT32_MAX);
            if (overflow) {
                carry = 1;
            }
            sum = tmp;
        }
        
        if (i < b->count) {
            uint64_t tmp = sum + b->parts[i];
            char overflow = (tmp > UINT32_MAX);
            if (overflow) {
                carry = 1;
            }
            sum = tmp;
        }

        result->parts[i] = (uint32_t)sum;
    }
    
    if (carry != 0) {
        result->parts[i] = carry;
        result->count = i;
    }
    else {
        result->count = count;
    }
    
    normalize(result);
    
    return result;
}

CBigInt *CBigIntSubtract(CBigInt *a, CBigInt *b)
{
    if (a->sign != b->sign) {
        if (a->sign) {
            CBigInt a1;
            a1.sign = 0;
            a1.parts = a->parts;
            a1.count = a->count;
            
            CBigInt *result = CBigIntAdd(&a1, b);
            result->sign = !result->sign;
            
            return result;
        }
        else {
            CBigInt b1;
            b1.sign = 0;
            b1.parts = b->parts;
            b1.count = b->count;
            
            return CBigIntAdd(a, &b1);
        }
    }
    
    if (a->sign) {
        CBigInt a1;
        a1.sign = !a->sign;
        a1.parts = a->parts;
        a1.count = a->count;

        CBigInt b1;
        b1.sign = !b->sign;
        b1.parts = b->parts;
        b1.count = b->count;

        CBigInt *result = CBigIntAdd(&a1, &b1);
        
        result->sign = !result->sign;
        
        return result;
    }
    
    int count = max(a->count, b->count);
    CBigInt *result = CBigIntCreateWithCapacity(count);
    
    uint32_t carry = 0;
    int i = 0;
    for (; i < count; ++i)
    {
        uint32_t difference = carry;
        carry = 0;
        
        if (i < a->count) {
            uint32_t tmp = a->parts[i] - difference;
            char underflow = (tmp > a->parts[i]);
            if (underflow) {
                carry = 1;
            }
            difference = tmp;
        }

        if (i < b->count) {
            uint32_t tmp = difference - b->parts[i];
            char underflow = (tmp > difference);
            if (underflow) {
                carry = 1;
            }
            difference = tmp;
        }

        
        result->parts[i] = difference;
    }
    
    result->count = count;
    
    normalize(result);
    
    return result;
}

void CBigIntInplaceAdd(CBigInt *a, CBigInt *b)
{
    uint32_t count = max(a->count, b->count);
    CBigIntExtendCapacity(a, count + 1);
    
    uint32_t carry = 0;
    uint32_t i = 0;
    for (; i < count; ++i)
    {
        uint64_t sum = carry;
        carry = 0;
        
        if (i < a->count) {
            uint64_t tmp = sum + a->parts[i];
            char overflow = (tmp > UINT32_MAX);
            if (overflow) {
                carry = 1;
            }
            sum = tmp;
        }
        
        if (i < b->count) {
            uint64_t tmp = sum + b->parts[i];
            char overflow = (tmp > UINT32_MAX);
            if (overflow) {
                carry = 1;
            }
            sum = tmp;
        }
        
        a->parts[i] = (uint32_t)sum;
    }
    
    if (carry != 0) {
        a->parts[i] = carry;
        a->count = i;
    }
    else {
        a->count = count;
    }
    
    normalize(a);
}

static void CBigIntShiftLeft(CBigInt *a)
{
    const uint32_t highestBitMask = 0x80000000UL;
    if ((a->parts[a->count - 1] & highestBitMask) != 0) {
        CBigIntExtendCapacity(a, a->count + 1);
        a->parts[a->count] = 0;
        a->count += 1;
    }
    
    uint32_t oldCarry = 0;
    uint32_t carry = 0;
    for (int i = 0; i < a->count; ++i)
    {
        uint32_t v = a->parts[i];
        carry = (v & highestBitMask) ? 1 : 0;
        v <<= 1;
        a->parts[i] = v | oldCarry;
        oldCarry = carry;
    }
}

CBigInt *CBigIntMultiplyByAddAndShift(CBigInt *a, CBigInt *b);
CBigInt *CBigIntMultiplyByAddAndShift(CBigInt *a, CBigInt *b)
{
    int aCount = a->count;
    int bCount = b->count;
    int resultCount = aCount + bCount;
    
    CBigInt *result = CBigIntCreateWithCapacity(resultCount);
    CBigInt *aShifted = CBigIntCopy(a);
    
    for (int i=0; i < aCount * 8 * sizeof(uint32_t); ++i)
    {
        if (CBigIntIsBitSet(b, i))
        {
            CBigIntInplaceAdd(result, aShifted);
        }
        CBigIntShiftLeft(aShifted);
    }
    
    return result;
}

CBigInt *CBigIntMultiply(CBigInt *a, CBigInt *b)
{
//    return CBigIntMultiplyByAddAndShift(a, b);
    
#if 1
    int aCount = a->count;
    int bCount = b->count;
    int resultCount = aCount + bCount;
    
    CBigInt *result = CBigIntCreateWithCapacity(resultCount);
    
    uint32_t *aParts = a->parts;
    uint32_t *bParts = b->parts;
    
    for (int i = 0; i < aCount; ++i)
    {
        for (int j = 0; j < bCount; ++j)
        {
            uint64_t r = (uint64_t)aParts[i] * (uint64_t)bParts[j];
            
            if (r == 0) {
                continue;
            }
            
            uint64_t hi = (r >> 32);
            uint64_t lo = r & 0xffffffff;
            
            uint64_t tmp = result->parts[i + j] + lo;
            char overflow = (tmp > UINT32_MAX);
            if (overflow) {
                hi += 1;
            }
            result->parts[i + j] = (uint32_t)tmp;
            
            uint64_t temp = hi;
            int index = i + j + 1;
            for (;;)
            {
                tmp = result->parts[index] + temp;
                char overflow = (tmp > UINT32_MAX);
                result->parts[index] = (uint32_t)tmp;
                if (overflow) {
                    temp = 1;
                    index += 1;
                }
                else {
                    break;
                }
            }
        }
    }
    
    result->count = resultCount;
    
    return result;
#endif
}

static CBigInt *CBigIntDivideByUInt(CBigInt *u, uint32_t v, uint32_t *remainder)
{
    int shift = sizeof(uint32_t) * 8;
    int64_t b = 1ULL << shift;
    uint64_t r = 0;
    int n = u->count;
    
    CBigInt *result = CBigIntCreateWithCapacity(n);
    
    for (int i = n - 1; i >= 0; --i) {
        uint64_t t = r * b + u->parts[i];
        
        uint64_t q = t / v;
        r = t % v;
        
        result->parts[i] = (uint32_t)q;
    }
    
    result->count = n;
    
    normalize(result);
    
    if (remainder != NULL) {
        *remainder = (uint32_t)r;
    }
    
    return result;
}

int CBigIntIsZero(CBigInt *b)
{
    return b->count == 0 || (b->count == 1 && b->parts[0] == 0);
}

int CBigIntIsBitSet(CBigInt *b, int bitNumber)
{
    int partSize    = sizeof(uint32_t) * 8;
    int partNumber  = bitNumber / partSize;
    int bit         = bitNumber % partSize;
    
    if (partNumber >= b->count) {
        return 0;
    }
    
    return (b->parts[partNumber] & (1UL << bit)) != 0;
}

CBigInt *CBigIntDivide(CBigInt *u, CBigInt *v, CBigInt **remainder)
{
    // This is an implementation of Algorithm D in
    // "The Art of Computer Programming" by Donald E. Knuth, Volume 2, Seminumerical Algorithms, 3rd edition, p. 272
    if (CBigIntIsZero(v)) {
        // handle error
        return CBigIntCreateWithCapacity(0);
    }
    
    int n = v->count;
    int m = u->count - n;
    
    if (m < 0) {
        if (remainder != NULL) {
            *remainder = CBigIntCopy(u);
        }
        return CBigIntCreateWithCapacity(0);
    }
    
    if (n == 1 && m == 0) {
        uint32_t p = u->parts[0] / v->parts[0];
        if (remainder != NULL) {
            uint32_t rem = u->parts[0] % v->parts[0];
            *remainder = CBigIntCreateWithParts(&rem, 1);
        }

        return CBigIntCreateWithParts(&p, 1);
    }
    else if (n == 1) {
        uint32_t divisor = v->parts[0];
        if (v->sign) {
            assert(0 && "Division by negative number is not implemented.");
            return CBigIntCreateWithCapacity(0);
        }
        
        uint32_t rem;
        CBigInt *result = CBigIntDivideByUInt(u, divisor, &rem);
        if (remainder != NULL) {
            *remainder = CBigIntCreateWithParts(&rem, 1);
        }
        
        return result;
    }
    
    CBigInt *copiedU = CBigIntCopyWithCapacity(u, u->count + 1);
    u = copiedU;
    
    CBigInt *result = CBigIntCreateWithCapacity(m + 1);
    result->count = m + 1;
    
    // normalize, so that v[0] >= base/2 (i.e. 2^31 in our case)
    int shift = (sizeof(uint32_t) * 8) - 1;
    uint32_t mask = (uint32_t)((1ULL << (sizeof(uint32_t) * 8)) - 1);
    uint32_t highestBitMask = 1 << shift;
    uint32_t hi = v->parts[n - 1];
    uint32_t d = 1;
    while ((hi & highestBitMask) == 0)
    {
        hi = hi << 1;
        d  = d  << 1;
    }
    
    if (d != 1) {
        CBigInt dd = {.capacity = 1, .count = 1, .parts = &d, .sign = 0};
        
        CBigInt *newU = CBigIntMultiply(u, &dd);
        CBigInt *newV = CBigIntMultiply(v, &dd);
        
        CBigIntFree(u);
        u = newU;
        
        CBigIntFree(v);
        v = newV;
    }
    
    if (u->count < m + n + 1) {
        int count = u->count;
        if (count + 1 >= u->capacity) {
            CBigIntExtendCapacity(u, count + 1);
        }
        
        u->parts[count] = 0;
        u->count = count + 1;
    }
    
    uint32_t bits = sizeof(uint32_t) * 8;
    uint64_t b = 1ULL << bits;
    for (int j = m; j >= 0; --j)
    {
        // D3. Calculate q
        uint64_t dividend = (((uint64_t)u->parts[j + n]) << bits) + u->parts[j + n - 1];
        uint64_t denominator = v->parts[n - 1];
        uint64_t q = dividend / denominator;
        uint64_t r = dividend % denominator;
        
        if (q != 0) {
            while (q == b || (q * v->parts[n - 2] > (r << bits) + u->parts[j + n - 2])) {
                
                q = q - 1;
                r = r + denominator;
                
                if (r > b) {
                    break;
                }
            }
            
            
            // D4. Multiply and subtract
            CBigInt *vtemp = CBigIntCopyWithCapacity(v, v->count + 1);
            vtemp->parts[v->count] = 0;
            
            uint32_t qq[] = {(uint32_t)(q >> bits), (uint32_t)(q & mask)};
            uint32_t *qParts = qq;
            int qCount = 2;
            if (q < b) {
                qParts = &qq[1];
                qCount = 1;
            }
            CBigInt a = {.count = n + 1, .capacity = n + 1, .parts = &u->parts[j]};
            CBigInt b = {.count = qCount, .capacity = qCount, .parts = qParts, .sign = 0};
            

            CBigInt *t1 = CBigIntMultiply(vtemp, &b);
            CBigInt *temp = CBigIntSubtract(&a, t1);
            CBigIntFree(t1);

//            var temp = BigIntType(u.parts[j...j+n]) - vtemp * BigIntType(q)
  
            // D6. handle negative case
            if (temp->sign) {
                // handle negative case
                CBigInt *t2 = CBigIntAdd(temp, vtemp);
                CBigIntFree(temp);
                temp = t2;
                q = q - 1;
            }
            
            int count = temp->count;
            for (int i = 0; i < n; ++i) {
                u->parts[j + i] = i < count ? temp->parts[i] : 0;
            }
            
            CBigIntFree(temp);
        }
        
        result->parts[j] = (uint32_t)q;
    }
    
    result->sign = (u->sign != v->sign);

    if (remainder != NULL) {
        CBigInt a = {.count = n, .capacity = n, .parts = u->parts, .sign = u->sign};
        CBigInt dd = {.count = 1, .capacity = 1, .parts = &d, .sign = 0};
        *remainder = CBigIntDivide(&a, &dd, NULL);
    }
    
    normalize(result);
    
    return result;
}

CBigInt *CBigIntMod(CBigInt *u, CBigInt *v)
{
    CBigInt *remainder;
    
    CBigInt *result = CBigIntDivide(u, v, &remainder);
    CBigIntFree(result);
    
    return remainder;
}

CBigInt *CBigIntModularPowerWithBigIntExponent(CBigInt *base, CBigInt *exponent, CBigInt *modulus)
{
    int numBits = exponent->count * sizeof(uint32_t) * 8;
    
    CBigInt *result = CBigIntCreateWithInt(1);

    CBigInt * r = CBigIntMod(base, modulus);
    for (int i = 0; i < numBits; ++i)
    {
        if (CBigIntIsBitSet(exponent, i)) {
            CBigInt *temp1 = CBigIntMultiply(result, r);
            CBigInt *temp2 = CBigIntMod(temp1, modulus);
            
            CBigIntFree(temp1);
            CBigIntFree(result);

            result = temp2;
        }
        
        CBigInt *temp3 = CBigIntMultiply(r, r);
        CBigInt *temp4 = CBigIntMod(temp3, modulus);
        CBigIntFree(r);
        CBigIntFree(temp3);
        r = temp4;
    }
    
    return result;
}
