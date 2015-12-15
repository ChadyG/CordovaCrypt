//
//  RSA Wrapper
//
//  Created by Reejo Samuel on 2/17/14.
//  Copyright (c) 2014 Clapp Inc. All rights reserved.
//
// 
// 	MIT License
// 
// 	Permission is hereby granted, free of charge, to any person obtaining
// 	a copy of this software and associated documentation files (the
// 	"Software"), to deal in the Software without restriction, including
// 	without limitation the rights to use, copy, modify, merge, publish,
// 	distribute, sublicense, and/or sell copies of the Software, and to
// 	permit persons to whom the Software is furnished to do so, subject to
// 	the following conditions:
// 
// 	The above copyright notice and this permission notice shall be
// 	included in all copies or substantial portions of the Software.
// 
// 	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// 	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// 	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// 	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// 	LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// 	OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// 	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import <Foundation/Foundation.h>

typedef void (^GenerateSuccessBlock)(void);

@interface RSA : NSObject

/**
 *  Steps to Follow
 *
 *  Step 1: Start a sharedInstance
 *  Step 2: Set the Public, Private and Server Public Identifiers
 *  Step 3: Generate public/private keys for device
 *  Step 4: Set server public key
 *  Step 5: Encrypt/Decrypt using helpers
 *
 *  Note: Public, private identifiers can be any string used
 *        to uniquely identify the keys stored in keychain.
 */

+ (id)sharedInstance;
- (void)setIdentifierForPublicKey:(NSString *)pubIdentifier
                       privateKey:(NSString *)privIdentifier
                  serverPublicKey:(NSString *)servPublicIdentifier;

- (void)generateKeyPairRSACompleteBlock:(GenerateSuccessBlock)_success;


// returns Base64 encoded strings


// Encryption Method

- (NSString *)encryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)encryptUsingPrivateKeyWithData:(NSData*)data;

// Decrypt Methods

- (NSString *)decryptUsingPublicKeyWithData:(NSData *)data;
- (NSString *)decryptUsingPrivateKeyWithData:(NSData*)data;

// SET / GET Public Key

- (BOOL)setPublicKey:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyPEM;
- (NSString *)getPublicKeyDER;
- (NSString *)getPublicKeyAsBase64;

- (NSString *)getServerPublicKey;

// Encrypt using Server Public Key

- (NSString *)encryptUsingServerPublicKeyWithData:(NSData *)data;

//  SET / GET Public key for Java Servers

- (BOOL)setPublicKeyFromJavaServer:(NSString *)keyAsBase64;
- (NSString *)getPublicKeyAsBase64ForJavaServer;



@end