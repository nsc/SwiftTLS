//
//  openssl_utils.c
//  SwiftTLS
//
//  Created by Nico Schmidt on 06.06.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

#include <stdlib.h>

int  RAND_bytes(unsigned char *buf,int num)
{
    arc4random_buf(buf, num);
    
    return 1;
}

int  RAND_pseudo_bytes(unsigned char *buf,int num)
{
    return RAND_bytes(buf, num);
}

void RAND_add(const void *buf,int num,double entropy)
{
}

int CRYPTO_mem_ctrl(int mode)
{
    return 0;
}
