package com.scg.crypto;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.ParcelUuid;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public final class CryptoRSA
{
  private static final String RSA_MODE = "RSA/NONE/PKCS1Padding";
  private static final String PEM_HEADER = "-----BEGIN PUBLIC KEY-----\n";
  private static final String PEM_FOOTER = "-----END PUBLIC KEY-----";

  private static KeyPair keyPair;


  public static void initialize()
  {
    try {
      //KeyPairGenerator just takes RSA with no options
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
      kpg.initialize(2048);
      keyPair = kpg.genKeyPair();

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  public static String getPublicKey()
  {
    String strKey = null;
    String pemKey = PEM_HEADER;
    byte[] keyBytes = null;
    Key publicKey = keyPair.getPublic();
  //Build PEM
    keyBytes = publicKey.getEncoded();
    strKey = Base64.encodeToString(keyBytes, Base64.DEFAULT);
    return pemKey.concat(strKey.concat(PEM_FOOTER));
  }

  public static String encrypt(String message)
  {
    byte[] encodedBytes = null;
    Key publicKey = null;

    try {
      Cipher cipher = Cipher.getInstance(RSA_MODE);
      publicKey = keyPair.getPublic();
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      encodedBytes = cipher.doFinal(message.getBytes());
    } catch (Exception e) {
      e.printStackTrace();
    }

    return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
  }

  public static String decrypt(String message)
  {
    byte[] encodedBytes = Base64.decode(message, Base64.DEFAULT);
    byte[] decodedBytes = null;
    Key privateKey = null;

    Cipher cipher = null;
    try {
      cipher = Cipher.getInstance(RSA_MODE);
      privateKey = keyPair.getPrivate();
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      String algo = cipher.getAlgorithm();
      int bsize = cipher.getBlockSize();
      int insize = encodedBytes.length;
      decodedBytes = cipher.doFinal(encodedBytes);
    } catch (Exception e) {
      e.printStackTrace();
    }

    return Base64.encodeToString(decodedBytes, Base64.DEFAULT);
  }
}