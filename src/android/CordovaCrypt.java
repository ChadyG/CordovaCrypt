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

import javax.crypto;
import javax.crypto.interfaces;
import javax.crypto.spec;

public class CordovaCrypt extends CordovaPlugin
{
  private static final String TAG = "SCG";
  //Argument Keys
  private final String keyError = "error";
  private final String keyMessage = "message";
  private final String keyData = "data";
  private final String keyToken = "token";
  private final String keyPrivate = "privatekey";
  private final String keyPublic = "publickey";
  private final String isInitialized = "isInitialized";

  private final String statusInitialized = "isInitialized";
  private final String statusTokenSet = "set";

  private final String errorParams = "params";
  private final String errorMessage = "Missing parameter message";
  private final String errorToken = "Token not set.";
  private final String errorPrivate = "Missing parameter privatekey";
  private final String errorPublic = "Missing parameter publickey";
  private final String errorEncrypt = "Could not encrypt";
  private final String errorDecrypt = "Could not decrypt";

  //enable/disable logging
  public static boolean DEBUG_LOG_ENABLED = true;

  private String token;

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if ("initialize".equals(action)) {
      this.initializeAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("setToken".equals(action)) {
      this.setTokenAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
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
    if ("encryptPrivate".equals(action)) {
      this.encryptRSAAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("decryptPublic".equals(action)) {
      this.decryptRSAAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("getPublicKey".equals(action)) {
      this.getPublicKeyAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    return false;  // Returning false results in a "MethodNotFound" error.
  }


  public void initializeAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();

    log("initializeAction");

    try {
      CryptoRSA.initialize();

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

  public void setTokenAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    token = getToken(obj);

    log("setTokenAction");

    try {
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

  public void getPublicKeyAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);

    log("getPublicKeyAction");

    try {
      String pemKey = CryptoRSA.getPublicKey();

      addProperty(returnObj, keyPublic, pemKey);
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

  public void encryptPublicAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);

    log("encryptPublicAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
      return;
    }

    try {
      String encryptedMsg = CryptoRSA.encrypt(message);

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

  public void decryptPrivateAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);

    log("decryptPrivateAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
      return;
    }

    try {
      String decryptedMsg = CryptoRSA.decrypt( message);

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

  public void encryptAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);
    Long data = getData(obj);
    String encryptedMsg;

    log("encryptAction obj: " + obj.toString() + "\n message: " + message);
    if (token == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorToken);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
      return;
    }

    try {

      if (data != null) {
        encryptedMsg = AESCrypt.encryptData(this.token, data);
      }else
      if (message != null) {
        encryptedMsg = AESCrypt.encrypt(this.token, message);
      }
      else
      {
        addProperty(returnObj, keyError, errorParams);
        addProperty(returnObj, keyMessage, errorMessage);
        PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
        pluginResult.setKeepCallback(true);
        callbackContext.sendPluginResult(pluginResult);
        return;
      }

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

    log("decryptAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
      return;
    }
    if (token == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorToken);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
      return;
    }

    try {
      String decryptedMsg = AESCrypt.decrypt(this.token, message);

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
    //Get the message string from arguments
    String value = obj.optString(keyMessage, null);
    return value;
  }

  private Long getData(JSONObject obj)
  {
    //Get the message string from arguments
    Long value = obj.optLong(keyData, null);
    return value;
  }

  private String getToken(JSONObject obj)
  {
    //Get the token string from arguments
    String value = obj.optString(keyToken, null);
    return value;
  }

  private String getPublicKey(JSONObject obj)
  {
    //Get the public key string from arguments
    String value = obj.optString(keyPublic, null);
    return value;
  }

  private String getPrivateKey(JSONObject obj)
  {
    //Get the private key string from arguments
    String value = obj.optString(keyPrivate, null);
    return value;
  }



  private static void log(String what) {
    if (DEBUG_LOG_ENABLED)
      Log.d(TAG, what);
  }
}
