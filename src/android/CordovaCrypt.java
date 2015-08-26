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
import android.util.Log;

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

import com.scottyab.aescrypt.AESCrypt;
import java.security.GeneralSecurityException;

public class CordovaCrypt extends CordovaPlugin
{
  private static final String TAG = "SCG";
  //Argument Keys
  private final String keyError = "error";
  private final String keyMessage = "message";
  private final String keyPrivate = "privatekey";
  private final String keyPublic = "publickey";

  private final String errorParams = "params";
  private final String errorEncrypt = "encrypt";
  private final String errorDecrypt = "decrypt";
  private final String errorMessage = "Missing parameter message";
  private final String errorPrivate = "Missing parameter privatekey";
  private final String errorPublic = "Missing parameter publickey";

  //enable/disable logging
  public static boolean DEBUG_LOG_ENABLED = true;

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
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);
    String privatekey = getAESPrivateKey(obj);

    log("encryptAction obj: " + obj.toString() + "\n message: " + message + " key: " + privatekey);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }
    if (privatekey == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorPrivate);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    try {
      String encryptedMsg = AESCrypt.encrypt(privatekey, message);

      addProperty(returnObj, keyMessage, encryptedMsg);

      PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }catch (GeneralSecurityException e){
      addProperty(returnObj, keyError, errorEncrypt);
      addProperty(returnObj, keyMessage, e.getMessage());
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }
  }

  public void decryptAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);
    String publickey = getAESPublicKey(obj);

    log("decryptAction obj: " + obj.toString() + "\n message: " + message + " key: " + publickey);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }
    if (publickey == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorPublic);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    try {
      String decryptedMsg = AESCrypt.decrypt(publickey, message);

      addProperty(returnObj, keyMessage, decryptedMsg);

      PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }catch (GeneralSecurityException e){
      addProperty(returnObj, keyError, errorDecrypt);
      addProperty(returnObj, keyMessage, e.getMessage());
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }
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



  private static void log(String what) {
    if (DEBUG_LOG_ENABLED)
      Log.d(TAG, what);
  }
}
