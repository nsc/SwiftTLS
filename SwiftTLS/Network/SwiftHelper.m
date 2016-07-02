//
//  SwiftHelper.c
//
//  Created by Nico Schmidt on 17.02.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

#include "SwiftHelper.h"

#import <fcntl.h>
int NSC_setFileFlags(int fd, int flags) {
    return fcntl(fd, F_SETFL, flags);
}

int NSC_getFileFlags(int fd) {
    return fcntl(fd, F_GETFL, 0);
}
