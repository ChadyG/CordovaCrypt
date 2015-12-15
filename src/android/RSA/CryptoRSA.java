package com.scg.crypto;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.ParcelUuid;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto;
import javax.crypto.interfaces;
import javax.crypto.spec;


public final class CryptoRSA
{
  private static KeyPair keyPair;


  public static void initialize()
  {
	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	kpg.initialize(2048);
	this.keyPair = kpg.genKeyPair();
  }

  public static String getPublicKey()
  {
    Key publicKey = null;
	publicKey = this.keyPair.getPublic();
	//Build PEM
  }

  public static String encrypt(String message)
  {
  	byte[] encodedBytes = null;

  	Cipher c = Cipher.getInstance("RSA");
    c.init(Cipher.ENCRYPT_MODE, privateKey);
    encodedBytes = c.doFinal(theTestText.getBytes());

    return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
  }

  public static String decrypt(String data)
  {
  	byte[] decodedBytes = null;

	Cipher c = Cipher.getInstance("RSA");
    c.init(Cipher.DECRYPT_MODE, publicKey);
    decodedBytes = c.doFinal(encodedBytes);

    return Base64.encodeToString(decodedBytes, Base64.DEFAULT);
  }
}