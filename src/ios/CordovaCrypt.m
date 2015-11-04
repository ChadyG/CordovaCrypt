#import "CordovaCrypt.h"
#import "AESCrypt.h"
#import "RSA.h"

//Plugin Name
NSString *const pluginName = @"CordovaCrypt";

//Object Keys
NSString *const keyMessage = @"message";
NSString *const keyToken = @"token";
NSString *const keyPublic = @"publickey";
NSString *const keyPrivate = @"privatekey";
NSString *const keyIsInitialized = @"isInitialized";

//Status Types
NSString *const statusInitialized = @"initialized";
NSString *const statusTokenSet = @"set";


@interface CordovaCrypt ()
{
  NSString *token;
  RSA *rsa;
}
@end


@implementation CordovaCrypt


- (void)initialize:(CDVInvokedUrlCommand*)command
{
  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: statusInitialized, keyIsInitialized, nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  rsa = [RSA sharedInstance];
  [rsa setIdentifierForPublicKey:@"com.scg.publicKey"
                      privateKey:@"com.scg.privateKey"
                 serverPublicKey:@"com.scg.serverPublicKey"];

  [rsa generateKeyPairRSACompleteBlock:^{
    //NSLog(@"Key generated and public key shown");
  }];


  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// AES

- (void)setToken:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];
  token = [self getToken:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: statusTokenSet, keyToken, nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)encrypt:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                             [AESCrypt encrypt:message key:token], keyMessage,
                             nil];
  CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK  messageAsDictionary:returnObj];
  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                              [AESCrypt decrypt:message key:token], keyMessage,
                              nil];
  CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK  messageAsDictionary:returnObj];
  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// RSA

- (void)encryptPrivate:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                             [rsa encryptUsingServerPublicKeyWithData:[message dataUsingEncoding:NSUTF8StringEncoding]], keyMessage,
                             nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)decryptPublic:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                             [rsa decryptUsingPrivateKeyWithData:[[NSData alloc] initWithBase64EncodedString:message options:0]], keyMessage,
                             nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getPublicKey:(CDVInvokedUrlCommand*)command
{
  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: [rsa getServerPublicKey], keyPublic, nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


-(NSDictionary*) getArgsObject:(NSArray *)args
{
  if (args == nil)
  {
    return nil;
  }

  if (args.count != 1)
  {
    return nil;
  }

  NSObject* arg = [args objectAtIndex:0];

  if (![arg isKindOfClass:[NSDictionary class]])
  {
    return nil;
  }

  return (NSDictionary *)[args objectAtIndex:0];
}

// Reference

// -(NSData*) getValue:(NSDictionary *) obj
// {
//   NSString* string = [obj valueForKey:keyValue];

//   if (string == nil)
//   {
//     return nil;
//   }

//   if (![string isKindOfClass:[NSString class]])
//   {
//     return nil;
//   }

//   NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];

//   if (data == nil || data.length == 0)
//   {
//     return nil;
//   }

//   return data;
// }

// -(void) addValue:(NSData *) bytes toDictionary:(NSMutableDictionary *) obj
// {
//   NSString *string = [bytes base64EncodedStringWithOptions:0];

//   if (string == nil || string.length == 0)
//   {
//     return;
//   }

//   [obj setValue:string forKey:keyValue];
// }


-(NSString*) getMessage:(NSDictionary *)obj
{
  NSString* messageString = [obj valueForKey:keyMessage];

  if (messageString == nil)
  {
    return nil;
  }

  if (![messageString isKindOfClass:[NSString class]])
  {
    return nil;
  }

  return messageString;
}

-(NSString*) getPrivateKey:(NSDictionary *)obj
{
  NSString* keyString = [obj valueForKey:keyPrivate];

  if (keyString == nil)
  {
    return nil;
  }

  if (![keyString isKindOfClass:[NSString class]])
  {
    return nil;
  }

  return keyString;
}

-(NSString*) getPublicKey:(NSDictionary *)obj
{
  NSString* keyString = [obj valueForKey:keyPublic];

  if (keyString == nil)
  {
    return nil;
  }

  if (![keyString isKindOfClass:[NSString class]])
  {
    return nil;
  }

  return keyString;
}

-(NSString*) getToken:(NSDictionary *)obj
{
  NSString* tokenString = [obj valueForKey:keyToken];

  if (tokenString == nil)
  {
    return nil;
  }

  if (![tokenString isKindOfClass:[NSString class]])
  {
    return nil;
  }

  return tokenString;
}

@end
