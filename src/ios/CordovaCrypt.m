#import "CordovaCrypt.h"
#import "AESCrypt.h"
#import "RSA.h"
#import "CryptoRSA.h"
#import "NSData+Base64.h"


#define USE_LIBCRYPT 1
//#undef USE_LIBCRYPT
//Plugin Name
//NSString *const pluginName = @"CordovaCrypt";

//Object Keys
NSString *const scgKeyMessage = @"message";
NSString *const scgKeyData = @"data";
NSString *const scgKeyToken = @"token";
NSString *const scgKeyPublic = @"publickey";
NSString *const scgKeyPrivate = @"privatekey";
NSString *const scgKeyIsInitialized = @"isInitialized";
NSString *const scgKeyError = @"error";

//Status Types
NSString *const scgStatusInitialized = @"initialized";
NSString *const scgStatusTokenSet = @"set";

///Error Types
NSString *const scgErrorEncrypt = @"encrypt";
NSString *const scgErrorDecrypt = @"decrypt";
NSString *const scgNoArgObj = @"Argument object not found";
NSString *const scgBadEncrypt = @"Could not encrypt message;";
NSString *const scgBadDecrypt = @"Could not decrypt message;";

@interface CordovaCrypt ()
{
  NSString *token;
  RSA *rsa;
  CryptoRSA *crypt;
}
@end


@implementation CordovaCrypt


- (void)initialize:(CDVInvokedUrlCommand*)command
{
  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: scgStatusInitialized, scgKeyIsInitialized, nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];
    
#ifdef USE_LIBCRYPT
  crypt = [CryptoRSA sharedInstance];
    [crypt generateKeys];
#else
  rsa = [RSA sharedInstance];
  [rsa setIdentifierForPublicKey:@"com.scg.publicKey"
                      privateKey:@"com.scg.privateKey"
                 serverPublicKey:@"com.scg.serverPublicKey"];

  [rsa generateKeyPairRSACompleteBlock:^{
      //NSLog(@"Key generated and public key shown");
      
//      crypt = [CryptoRSA sharedInstance];
//      [crypt setPublicKeyStr:[rsa getPublicKeyPEM]];
//      NSString* message = @"Hello World";
//      NSString* encTest = [crypt encrypt:[message dataUsingEncoding:NSUTF8StringEncoding]];
//      NSString* decrypted = [rsa decryptUsingPrivateKeyWithData:[NSData dataFromBase64String:encTest]];
//      NSLog([NSString stringWithFormat:@"encrypted %@", message]);
//      NSLog([NSString stringWithFormat:@"decrypted %@", decrypted]);
  }];
#endif

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// AES

- (void)setToken:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  token = [self getToken:obj];
    
  NSData *tdata = [token dataUsingEncoding:NSUTF8StringEncoding];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: scgStatusTokenSet, scgKeyToken, nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)encrypt:(CDVInvokedUrlCommand*)command
{
    NSDictionary *obj = [self getArgsObject:command.arguments];
    NSString *message = [self getMessage:obj];
    NSData *data = [self getData:obj];
    
    NSDictionary* returnObj;
    if (message == nil)
    {
        returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                     [AESCrypt encryptData:data key:token], scgKeyMessage,
                     nil];
    }
    else{
        returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                     [AESCrypt encrypt:message key:token], scgKeyMessage,
                     nil];
    }
    
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK  messageAsDictionary:returnObj];
    [pluginResult setKeepCallbackAsBool:true];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];

  if (message == nil)
  {
    NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: scgErrorEncrypt, scgKeyError, scgNoArgObj, scgKeyMessage, nil];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:returnObj];
    [pluginResult setKeepCallbackAsBool:false];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    return;
  }

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                              [AESCrypt decrypt:message key:token], scgKeyMessage,
                              nil];
  CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK  messageAsDictionary:returnObj];
  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

// RSA

- (void)encryptPublic:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];
    
#ifdef USE_LIBCRYPT
  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                             [crypt encrypt:[message dataUsingEncoding:NSUTF8StringEncoding]], scgKeyMessage,
                             nil];
#else
    
    NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                               [rsa encryptUsingPublicKeyWithData:[message dataUsingEncoding:NSUTF8StringEncoding]], scgKeyMessage,
                               nil];
#endif
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)decryptPrivate:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];
    
  if (message == nil)
  {
    NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: scgErrorEncrypt, scgKeyError, scgNoArgObj, scgKeyMessage, nil];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:returnObj];
    [pluginResult setKeepCallbackAsBool:false];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    return;
  }
    
#ifdef USE_LIBCRYPT
  NSString* decrypted = [crypt decrypt:[NSData dataFromBase64String:message]];
#else
    NSString* decrypted = [rsa decryptUsingPrivateKeyWithData:[NSData dataFromBase64String:message]];
#endif
    
  if (decrypted == nil)
  {
    NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: scgErrorEncrypt, scgKeyError, scgBadDecrypt, scgKeyMessage, nil];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:returnObj];
    [pluginResult setKeepCallbackAsBool:false];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    return;
  }
    
  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys:
                             decrypted, scgKeyMessage,
                             nil];
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnObj];

  [pluginResult setKeepCallbackAsBool:true];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)getPublicKey:(CDVInvokedUrlCommand*)command
{
#ifdef USE_LIBCRYPT
    NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: [crypt getPublicKey], scgKeyPublic, nil];
#else
    NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: [rsa getPublicKeyPEM], scgKeyPublic, nil];
#endif
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
    NSString* messageString = [obj valueForKey:scgKeyMessage];
    
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

-(NSData*) getData:(NSDictionary *)obj
{
    NSData* dataMsg = [obj valueForKey:scgKeyData];
    
    if (dataMsg == nil)
    {
        return nil;
    }
    
    if ([dataMsg isKindOfClass:[NSNumber class]])
    {
        int integer = [(NSNumber*)dataMsg intValue];
        return [NSData dataWithBytes:&integer length:1];//sizeof(integer)];
    }
                
    if (![dataMsg isKindOfClass:[NSData class]])
    {
        return nil;
    }
    
    return dataMsg;
}

-(NSString*) getPrivKey:(NSDictionary *)obj
{
  NSString* keyString = [obj valueForKey:scgKeyPrivate];

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

-(NSString*) getPubKey:(NSDictionary *)obj
{
  NSString* keyString = [obj valueForKey:scgKeyPublic];

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
  NSString* tokenValue = [obj valueForKey:scgKeyToken];

  if (tokenValue == nil)
  {
    return nil;
  }

  if (![tokenValue isKindOfClass:[NSString class]])
  {
    return nil;
  }

  return tokenValue;
}

@end
