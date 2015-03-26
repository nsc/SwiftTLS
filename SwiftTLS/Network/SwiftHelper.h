//
//  SwiftHelper.h
//  Chat
//
//  Created by Nico Schmidt on 17.02.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

#include <stdint.h>

int NSC_setFileFlags(int fd, int flags);
int NSC_getFileFlags(int fd);

static inline void NSC_multiply64(uint64_t x, uint64_t y, uint64_t *lo, uint64_t *hi) {
    __uint128_t result = (__uint128_t)x * y;
    *lo = result;
    *hi = result >> 64;
}

