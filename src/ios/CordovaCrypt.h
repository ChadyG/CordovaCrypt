#import <Cordova/CDV.h>

@interface CordovaCrypt : CDVPlugin
{
}

-(void)encrypt:(CDVInvokedUrlCommand *)command;
-(void)decrypt:(CDVInvokedUrlCommand *)command;
@end
