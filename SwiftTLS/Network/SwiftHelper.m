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

NSDictionary<NSString *, NSString *> *base64Blocks(NSString *base64String)
{
    NSMutableDictionary<NSString *, NSString *> *result = [NSMutableDictionary new];
    
    NSError *error = nil;
    NSLog(@"%@", base64String);
    NSRegularExpression *beginRegEx = [NSRegularExpression regularExpressionWithPattern:@"-----BEGIN (.*)-----\\R"
                                                                                options:0
                                                                                  error:&error];
    
    NSRegularExpression *endRegEx = [NSRegularExpression regularExpressionWithPattern:@"-----END (.*)-----\\R"
                                                                              options:0
                                                                                error:&error];
    
    
    for (;;) {
        NSTextCheckingResult *beginMatch = [beginRegEx firstMatchInString:base64String options:0 range:NSMakeRange(0, base64String.length)];
        
        if (beginMatch == nil) {
            break;
        }
        NSRange beginRange = beginMatch.range;
        NSRange nameRange = [beginMatch rangeAtIndex:1];
        
        NSString *name = [base64String substringWithRange:nameRange];
        
        NSTextCheckingResult *endMatch = [endRegEx firstMatchInString:base64String options:0 range:NSMakeRange(0, base64String.length)];
        NSRange end = endMatch.range;
        
        NSString *base64Block = [base64String substringWithRange:NSMakeRange(beginRange.location + beginRange.length, end.location - (beginRange.location + beginRange.length))];
        
        result[name] = base64Block;
        
        base64String = [base64String substringFromIndex:end.location + end.length];
    }
    
    return result;
}
