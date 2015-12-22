//
//  CryptoRSA.m
//  iris-app
//
//  Created by Systematic Group on 12/10/15.
//
//

#import <Foundation/Foundation.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#import "NSString+Base64.h"
#import "iris_app-Swift.h"
#import "CryptoRSA.h"


const size_t kCSecAttrKeySizeInBitsLength = 2048;


@interface CryptoRSA (){
@private
    RSA *keyPair;
    RSA *publickey;
    RSA *privatekey;
    NSString *publicPEM;
    size_t publicBufferSize;
    size_t privateBufferSize;
    CryptoExportImportManager *cexport;
}

@end


@implementation CryptoRSA

//@synthesize publicKeyRef, privateKeyRef, serverPublicRef;


- (id)init{
    if (self = [super init]) {
        cexport = [[CryptoExportImportManager alloc] init];
    }return self;
}

+ (id)sharedInstance{
    static CryptoRSA *_rsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _rsa = [[self alloc] init];
    });
    return _rsa;
}

-(void) setPublicKey:(NSData *)key withSize:(size_t)size
{
    publicBufferSize = size;
    publicPEM = [cexport exportPublicKeyToPEM:key keyType:kSecAttrKeyTypeRSA keySize:kCSecAttrKeySizeInBitsLength];
    
    [self setPublicKeyStr:publicPEM];
}

-(void) setPublicKeyStr:(NSString *)key
{
    BIO *bio = BIO_new_mem_buf([key cStringUsingEncoding:NSUTF8StringEncoding], -1);
    NSLog(@"Pubkey from mem");
    
    
    if(bio == NULL)
    {
        NSLog(@"Error creating Bio");
    }
    
    publickey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    
    
    if(BIO_free(bio) == 0)
    {
        NSLog(@"Error freeing BIO");
    }
}

-(void) setPrivateKey:(NSData*)key withSize:(size_t)size
{
    privateBufferSize = size;
    NSString* private_pem = [cexport exportPublicKeyToPEM:key keyType:kSecAttrKeyTypeRSA keySize:kCSecAttrKeySizeInBitsLength];
    
    [self setPrivateKeyStr:private_pem ];
}

-(void) setPrivateKeyStr:(NSString *)key
{
    BIO *bio = BIO_new_mem_buf([key cStringUsingEncoding:NSUTF8StringEncoding], -1);
    
    if(bio == NULL)
    {
        NSLog(@"Error setting private key");
    }
    
    privatekey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    
    
    if(BIO_free(bio) == 0)
    {
        NSLog(@"Error freeing BIO");
    }
}


-(NSString*) getPublicKey
{
    return publicPEM;
}


-(void) generateKeys
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;
    
    char *keyPointer;
    NSUInteger keyLength;
    
    int             bits = 2048;
    unsigned long   e = RSA_F4;
    
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        NSLog(@"Error Set Word");
        return;
    }
    
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        NSLog(@"Error generate key");
        return;
    }
    
    // 2. save public key
    bp_public = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSA_PUBKEY(bp_public, r);
    if(ret != 1){
        NSLog(@"Error write public");
        return;
    }
    
    keyLength = (NSUInteger) BIO_get_mem_data(bp_public, &keyPointer);
    publicPEM = [[NSString alloc] initWithData:[NSData dataWithBytesNoCopy:keyPointer length:keyLength freeWhenDone:NO] encoding:NSUTF8StringEncoding];

    
    // 3. save private key
    bp_private = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    
    if (ret != 1){
        
        NSLog(@"Error write private");
    }
    
    keyPair = r;
    // 4. free
    
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    //RSA_free(r);
    BN_free(bne);
}


- (NSString*) encrypt:(NSData*)data
{
    int bytesWritten = 0;
    int totalBytes = 0;
    char* err;
    RSA* key = publickey;
    if(publickey == NULL)
    {
        key = keyPair;
    }
    NSMutableData *bits = [NSMutableData dataWithLength:RSA_size(key)];
    
    if(RSA_size(key) < [data length])
    {
        NSLog(@"ciphertext too small block returned will be: %d received size: %d", RSA_size(key), [data length]);
        return NULL;
    }
    
    bytesWritten = RSA_public_encrypt([data length], [data bytes], [bits mutableBytes], key, RSA_PKCS1_PADDING);
    
    if(bytesWritten <= 0)
    {
        NSLog(@"RSA error encrypting:");
        
        //free(err);
    }
    
    
    return [bits base64EncodedStringWithOptions:0];
}

- (NSString*) decrypt:(NSData*)data
{
    int bytesWritten = 0;
    int totalBytes = 0;
    char* err = 0;
    RSA* key = privatekey;
    NSMutableData *bits = [NSMutableData dataWithLength:[data length]];
    
    if(privatekey == NULL)
    {
        key = keyPair;
    }
    
    if(RSA_size(key) < [data length])
    {
        NSLog(@"plaintext too small: %d expected: %d", [data length], RSA_size(key));
        return NULL;
    }
    
    bytesWritten = RSA_private_decrypt([data length], [data bytes], [bits mutableBytes], key, RSA_PKCS1_PADDING);
    
    if(bytesWritten == -1)
    {
        
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        NSLog(@"RSA error decrypting: %s", err);
        
        //free(err);
    }
    
    [bits setLength:bytesWritten];
    
    NSString *decData = [[NSString alloc] initWithData:bits
                                              encoding:NSUTF8StringEncoding];
    if (decData == NULL) {
        decData = [NSString base64StringFromData:bits  length:[bits length]];
    }
    return decData;
}

@end
