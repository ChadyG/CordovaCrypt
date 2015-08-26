#import "CordovaCrypt.h"
#import "AESCrypt/AESCrypt.h"

//Plugin Name
NSString *const pluginName = @"CordovaCrypt";

//Object Keys
NSString *const keyMessage = @"message";
NSString *const keyPublic = @"privatekey";
NSString *const keyPrivate = @"publickey";

@implemenation CordovaCrypt


- (void)encrypt:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];
  NSString *privatekey = [self getPrivateKey:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: keyMessage, [AESCrypt encrypt message, password: privatekey], nil];
  CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:resultWithStatus:CDVCommandStatus_OK  messageAsDictionary:returnObj];
  [pluginResult setKeepCallbackAsBool:false];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
  NSDictionary *obj = [self getArgsObject:command.arguments];
  NSString *message = [self getMessage:obj];
  NSString *publickey = [self getPublicKey:obj];

  NSDictionary* returnObj = [NSDictionary dictionaryWithObjectsAndKeys: keyMessage, [AESCrypt decrypt message, password: publickey], nil];
  CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:resultWithStatus:CDVCommandStatus_OK  messageAsDictionary:returnObj];
  [pluginResult setKeepCallbackAsBool:false];
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

-(NSData*) getValue:(NSDictionary *) obj
{
  NSString* string = [obj valueForKey:keyValue];

  if (string == nil)
  {
    return nil;
  }

  if (![string isKindOfClass:[NSString class]])
  {
    return nil;
  }

  NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];

  if (data == nil || data.length == 0)
  {
    return nil;
  }

  return data;
}

-(void) addValue:(NSData *) bytes toDictionary:(NSMutableDictionary *) obj
{
  NSString *string = [bytes base64EncodedStringWithOptions:0];

  if (string == nil || string.length == 0)
  {
    return;
  }

  [obj setValue:string forKey:keyValue];
}


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
  NSString* messageString = [obj valueForKey:keyPrivate];

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

-(NSString*) getPublicKey:(NSDictionary *)obj
{
  NSString* messageString = [obj valueForKey:keyPublic];

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
