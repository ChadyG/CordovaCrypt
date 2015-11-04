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

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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

import javax.crypto.Cipher;

public class CordovaCrypt extends CordovaPlugin
{
  private static final String TAG = "SCG";
  //Argument Keys
  private final String keyError = "error";
  private final String keyMessage = "message";
  private final String keyToken = "token";
  private final String keyPrivate = "privatekey";
  private final String keyPublic = "publickey";
  private final String keyIsInitialized = "isInitialized";

  private final String statusToken = "set";
  private final String statusInitialized = "initialized";

  private final String errorParams = "params";
  private final String errorEncrypt = "encrypt";
  private final String errorDecrypt = "decrypt";
  private final String errorMessage = "Missing parameter message";
  private final String errorToken = "Missing parameter token";
  private final String errorPrivate = "Missing parameter privatekey";
  private final String errorPublic = "Missing parameter publickey";

  //enable/disable logging
  public static boolean DEBUG_LOG_ENABLED = true;
  public static String aesToken = "";
  public static Key publicRSAKey;
  public static Key privateRSAKey;

  @Override
  public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
    if ("initialize".equals(action)) {
      this.initializeAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("setToken".equals(action)) {
      this.setAESTokenAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("encrypt".equals(action)) {
      this.encryptAESAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("decrypt".equals(action)) {
      this.decryptAESAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("encryptPublic".equals(action)) {
      this.encryptRSAAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("decryptPrivate".equals(action)) {
      this.decryptRSAAction(args, callbackContext);
      callbackContext.success();
      return true;
    }
    if ("getPublicKey".equals(action)) {
      this.getRSAPublic(args, callbackContext);
      callbackContext.success();
      return true;
    }
    return false;  // Returning false results in a "MethodNotFound" error.
  }


  public void initializeAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();

    // Generate key pair for 1024-bit RSA encryption and decryption
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(1024);
      KeyPair kp = kpg.genKeyPair();
      publicRSAKey = kp.getPublic();
      privateRSAKey = kp.getPrivate();
    } catch (Exception e) {
      Log.e(TAG, "RSA key pair error");
    }

    log("initializeAction public: " + publicRSAKey + "\n private: " + privateRSAKey);
    addProperty(returnObj, keyIsInitialized, statusInitialized);

    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, returnObj);
    pluginResult.setKeepCallback(true);
    callbackContext.sendPluginResult(pluginResult);
  }

  // AES
  //////////////////////////////////////////////////

  public void setAESTokenAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String token = getAESToken(obj);

    log("setAESTokenAction obj: " + obj.toString() + "\n token: " + token);
    if (token == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorToken);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    aesToken = token;
    addProperty(returnObj, keyToken, statusToken);

    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, returnObj);
    pluginResult.setKeepCallback(true);
    callbackContext.sendPluginResult(pluginResult);
  }

  public void encryptAESAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);

    log("encryptAESAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    try {
      String encryptedMsg = AESCrypt.encryptKey(aesToken, message);

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

  public void decryptAESAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);

    log("decryptAESAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    try {
      String decryptedMsg = AESCrypt.decryptKey(aesToken, message);

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

  // RSA
  //////////////////////////////////////////////////


  public void encryptRSAAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);

    log("encryptRSAAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    try {
      byte[] encodedBytes = null;
      Cipher c = Cipher.getInstance("RSA");
      c.init(Cipher.ENCRYPT_MODE, privateRSAKey);
      encodedBytes = c.doFinal(message.getBytes());

      addProperty(returnObj, keyMessage, Base64.encodeToString(encodedBytes, Base64.DEFAULT));

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


  public void decryptRSAAction(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    JSONObject obj = getArgsObject(args);
    String message = getString(obj);

    log("decryptRSAAction obj: " + obj.toString() + "\n message: " + message);
    if (message == null) {
      addProperty(returnObj, keyError, errorParams);
      addProperty(returnObj, keyMessage, errorMessage);
      PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, returnObj);
      pluginResult.setKeepCallback(true);
      callbackContext.sendPluginResult(pluginResult);
    }

    try {
      byte[] decodedBytes = null;
      Cipher c = Cipher.getInstance("RSA");
      c.init(Cipher.DECRYPT_MODE, publicRSAKey);
      decodedBytes = c.doFinal(message.getBytes());

      addProperty(returnObj, keyMessage, new String(decodedBytes, "UTF-8"));

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


  public void getRSAPublic(JSONArray args, CallbackContext callbackContext)
  {
    JSONObject returnObj = new JSONObject();
    String key = Base64.encodeToString(publicRSAKey.getEncoded(), Base64.DEFAULT);

    log("getRSAPublic key: " + key);

    addProperty(returnObj, keyPublic, key);

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
    //Get the message string from arguments
    String message = obj.optString(keyMessage, null);
    return message;
  }

  private String getAESToken(JSONObject obj)
  {
    //Get the token string from arguments
    String token = obj.optString(keyToken, null);
    return token;
  }

  private String getPublicKey(JSONObject obj)
  {
    //Get the key string from arguments
    String key = obj.optString(keyPublic, null);
    return key;
  }

  private String getPrivateKey(JSONObject obj)
  {
    //Get the key string from arguments
    String key = obj.optString(keyPrivate, null);
    return key;
  }



  private static void log(String what) {
    if (DEBUG_LOG_ENABLED)
      Log.d(TAG, what);
  }
}
