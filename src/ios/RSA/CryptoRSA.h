//
//  CryptoRSA.h
//  iris-app
//
//  Created by Systematic Group on 12/10/15.
//
//

#ifndef CryptoRSA_h
#define CryptoRSA_h

#import <Foundation/Foundation.h>

@interface CryptoRSA : NSObject


+ (id)sharedInstance;

-(void) setPublicKey:(NSData*)key withSize:(size_t)size;
-(void) setPrivateKey:(NSData*)key withSize:(size_t)size;

-(NSString*) getPublicKey;

-(void) generateKeys;

- (NSString *)encrypt:(NSData *)data;
- (NSString *)decrypt:(NSData *)data;

@end

#endif /* CryptoRSA_h */
