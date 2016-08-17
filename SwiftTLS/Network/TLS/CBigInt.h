//
//  CBigInt.h
//  SwiftTLS
//
//  Created by Nico Schmidt on 12.09.15.
//  Copyright © 2015 Nico Schmidt. All rights reserved.
//

#ifndef CBigInt_h
#define CBigInt_h

#include <sys/types.h>

typedef struct {
    int count;
    int capacity;
    uint32_t *parts;
    char sign;
} CBigInt;

CBigInt *CBigIntCreateWithParts(uint32_t *parts, uint32_t count);
CBigInt *CBigIntCreateWithCapacity(uint32_t count);
CBigInt *CBigIntCreateWithHexString(const char *hexString);

CBigInt *CBigIntCopy(CBigInt *b);

void CBigIntFree(CBigInt *b);

int CBigIntIsBitSet(CBigInt *b, int bitNumber);

CBigInt *CBigIntAdd(CBigInt *a, CBigInt *b);
CBigInt *CBigIntSubtract(CBigInt *a, CBigInt *b);
CBigInt *CBigIntMultiply(CBigInt *a, CBigInt *b);
CBigInt *CBigIntDivide(CBigInt *u, CBigInt *v, CBigInt **remainder);
CBigInt *CBigIntMod(CBigInt *u, CBigInt *v);
CBigInt *CBigIntModularPowerWithBigIntExponent(CBigInt *base, CBigInt *exponent, CBigInt *modulus);

const char *CBigIntHexString(const CBigInt *b);
void CBigIntHexStringFree(const char *);

#endif /* CBigInt_h */
