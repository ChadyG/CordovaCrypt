#import <Cordova/CDV.h>

@interface CordovaCrypt : CDVPlugin

-(void)initialize:(CDVInvokedUrlCommand *)command;
-(void)setToken:(CDVInvokedUrlCommand *)command;
-(void)encrypt:(CDVInvokedUrlCommand *)command;
-(void)decrypt:(CDVInvokedUrlCommand *)command;
-(void)encryptPublic:(CDVInvokedUrlCommand *)command;
-(void)decryptPrivate:(CDVInvokedUrlCommand *)command;
-(void)getPublicKey:(CDVInvokedUrlCommand *)command;
@end
