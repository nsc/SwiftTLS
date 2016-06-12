//
//  SwiftHelper.h
//
//  Created by Nico Schmidt on 17.02.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

#include <stdint.h>

#include "CBigInt.h"

int NSC_setFileFlags(int fd, int flags);
int NSC_getFileFlags(int fd);

static inline void NSC_multiply64(uint64_t x, uint64_t y, uint64_t *lo, uint64_t *hi) {
    __uint128_t result = (__uint128_t)x * y;
    *lo = result;
    *hi = result >> 64;
}

static inline void NSC_divide64(uint64_t uhi, uint64_t ulo, uint64_t v, uint64_t *divhi, uint64_t *divlo, uint64_t *rem) {
    __uint128_t u = ((__uint128_t)uhi << 64) + ulo;
    
    __uint128_t q = u/v;
    *divhi = q >> 64;
    *divlo = q & 0xffffffffffffffffUL;
    *rem = u % v;
}
