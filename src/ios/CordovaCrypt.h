#import <Cordova/CDV.h>

@interface CordovaCrypt : CDVPlugin

-(void)encrypt:(CDVInvokedUrlCommand *)command;
-(void)decrypt:(CDVInvokedUrlCommand *)command;
-(void)encryptPrivate:(CDVInvokedUrlCommand *)command;
-(void)decryptPublic:(CDVInvokedUrlCommand *)command;
-(void)getPublicKey:(CDVInvokedUrlCommand *)command;
@end
