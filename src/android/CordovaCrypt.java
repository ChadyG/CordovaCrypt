package com.scg.crypto;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.ParcelUuid;
import android.os.Build;
import android.util.Base64;

import android.app.Activity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.scottyab.aescrypt;

public class CordovaCrypt extends CordovaPlugin
{
  //Argument Keys
  private final String keyMessage = "message";
  private final String keyPublic = "privatekey";
  private final String keyPrivate = "publickey";

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if ("encrypt".equals(action)) {
      this.encryptAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("decrypt".equals(action)) {
      this.decryptAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    return false;  // Returning false results in a "MethodNotFound" error.
  }


  public void encryptAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);
    String privatekey = getAESPrivateKey(obj);

    JSONObject returnObj = new JSONObject();
    String encryptedMsg = AESCrypt.encrypt(privatekey, message);

    addProperty(returnObj, keyMessage, encryptedMsg);

    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, returnObj);
    pluginResult.setKeepCallback(true);
    callbackContext.sendPluginResult(pluginResult);
  }

  public void decryptAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);
    String publickey = getAESPublicKey(obj);

    JSONObject returnObj = new JSONObject();
    String decryptedMsg = AESCrypt.encrypt(publickey, message);

    addProperty(returnObj, keyMessage, encryptedMsg);

    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, returnObj);
    pluginResult.setKeepCallback(true);
    callbackContext.sendPluginResult(pluginResult);
  }

  // Private methods
  //////////////////////////////////////////////////

  private JSONObject getArgsObject(JSONArray args)
  {
    if (args.length() == 1)
    {
      try
      {
        return args.getJSONObject(0);
      }
      catch (JSONException ex)
      {
      }
    }

    return null;
  }

  private void addProperty(JSONObject obj, String key, Object value)
  {
    //Believe exception only occurs when adding duplicate keys, so just ignore it
    try
    {
      obj.put(key, value);
    }
    catch (JSONException e)
    {

    }
  }

  private String getString(JSONObject obj)
  {
    //Get the address string from arguments
    String address = obj.optString(keyMessage, null);
    return address;
  }

  private String getAESPublicKey(JSONObject obj)
  {
    //Get the address string from arguments
    String address = obj.optString(keyPublic, null);
    return address;
  }

  private String getAESPrivateKey(JSONObject obj)
  {
    //Get the address string from arguments
    String address = obj.optString(keyPrivate, null);
    return address;
  }
}
