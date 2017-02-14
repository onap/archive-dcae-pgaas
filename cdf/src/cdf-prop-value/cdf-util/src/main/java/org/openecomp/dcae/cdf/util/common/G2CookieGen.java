/*
    Copyright (C) 2017 AT&T Intellectual Property. All rights reserved.  
 
    Licensed under the Apache License, Version 2.0 (the "License"); 
    you may not use this code except in compliance 
    with the License. You may obtain a copy of the License 
    at http://www.apache.org/licenses/LICENSE-2.0 
 
    Unless required by applicable law or agreed to in writing, software  
    distributed under the License is distributed on an "AS IS" BASIS,  
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or  
    implied. See the License for the specific language governing  
    permissions and limitations under the License. 

*/
package org.openecomp.dcae.cdf.util.common;

import javax.crypto.Cipher;
// import javax.crypto.SecretKey;
// import javax.crypto.KeyGenerator;
// import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
// import java.security.NoSuchAlgorithmException;
// import java.security.SecureRandom;
// import javax.crypto.SecretKey;
// import sun.misc.*;
import java.util.*;

public class G2CookieGen
{
  private Cipher cipher;
  private Key key = null;

  private static String alg = "DES";
  private static String desecb = "DES/ECB/PKCS5Padding";

  public static String G2_CLIENT_MEC_ID_1 = "MEC0001";
  private static String G2_CLIENT_MEC_ID_2 = "MEC0002";
  public static String G2_ENCRYPT_KEY = "secretK9";
  public static String G2_EPOCH_TM_STR = null;


  private static long G2_TM_DELTA_IN_MILLISECONDS = 10*60*1000;
  
  class G2WSSKey implements Key 
  {
    private final byte[] keyBytes;
    private final String alg;
  
    G2WSSKey(String algorithm, byte[] keyBytes) 
    {
      this.alg  = algorithm;
      this.keyBytes = keyBytes;
    }
  
    public String getAlgorithm() 
    {
      return alg;  
    }
    public String getFormat()    
    {
      return "RAW"; 
    }
    public byte[] getEncoded()   
    {
      return (byte[])keyBytes.clone(); 
    }
  }
  

  public G2CookieGen() {
    try {
      cipher = Cipher.getInstance(desecb);
    } catch (Throwable t) {
      System.err.println(t.toString());
      return;
    }
  }


  public static String getClient1MacId() {
    return G2_CLIENT_MEC_ID_1;
  }

  public static String getClient2MacId() {
    return G2_CLIENT_MEC_ID_2;
  }

  public static String toHexStringFromByteArray(byte[] bytes)
  {
    StringBuilder retString = new StringBuilder();
    for (int i = 0; i < bytes.length; ++i) {
      retString.append(Integer.toHexString(0x0100 + (bytes[i] & 0x00FF)).substring(1));
    }
    return retString.toString();
  }

  public static byte[] toByteArrayFromHexString(String hexStr)
  {
    byte[] bts = new byte[hexStr.length() / 2];
    for (int i = 0; i < bts.length; i++) {
      bts[i] = (byte) Integer.parseInt(hexStr.substring(2*i, 2*i+2), 16);
    }
    return bts;
  }

  public byte[] encryptData(String sData)
  {
    try {
      byte[] data = sData.getBytes();
      //System.out.println("Original data : " + new String(data));
	  if (key == null) setKey(G2_ENCRYPT_KEY);
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] result = cipher.doFinal(data);
      return result;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public String decryptData(byte[] sData)
  {
    try {
      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] result = cipher.doFinal(sData);
      return new String(result);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public String constructCookie(String mechId) {
	  return mechId + ":" + System.currentTimeMillis();
  }

  public void setKey(String g2EncryptKey)	{
      key =  new G2WSSKey(this.alg, g2EncryptKey.getBytes());
  }

  public String getEncryptedCookie(String mechId, String g2EncryptKey) {
      setKey(g2EncryptKey);
	  String tmp = constructCookie(mechId);
	  byte[] byteArray = this.encryptData(tmp);
      return this.toHexStringFromByteArray(byteArray);
  }

  public long getTimeMillisFromCookie(String cookie) {
    StringTokenizer tkn = new StringTokenizer(cookie,":");
    String tmStr = null;
    while (tkn.hasMoreTokens()) {
      tmStr = tkn.nextToken();
    }
    Long tmLong = new Long(tmStr);
    return tmLong.longValue();
  }

  public boolean isValid(long tm) {
    long ctm = System.currentTimeMillis();
System.out.println("Current Time="+ctm);
System.out.println("G2_TM_DELTA_IN_MILLISECONDS="+G2_TM_DELTA_IN_MILLISECONDS);
    if ( Math.abs(ctm - tm) <= G2_TM_DELTA_IN_MILLISECONDS ) {
      return true;
    }
    return false;
  }


  public static void main(String argv[]) {
    try {
      if (argv.length > 0) {
System.out.println("using Client MACID="+argv[0]);
         G2_CLIENT_MEC_ID_1 = argv[0];
       
      }

      if (argv.length > 1) {
         if (argv[1].length() == 8) {
System.out.println("using Key="+argv[1]);
            G2_ENCRYPT_KEY = argv[1];
         }
      }

      if (argv.length > 2) {
System.out.println("using Epoch Time (in seconds) ="+argv[2]);
            G2_EPOCH_TM_STR = argv[2];
      }


      G2CookieGen wssc = new G2CookieGen();

// System.out.println("tz_diff="+G2_CLIENT_TM_ZONE_TO_PDT_IN_MILLISECONDS);
System.out.println("macid="+G2_CLIENT_MEC_ID_1);

      String cookie = wssc.constructCookie(G2_EPOCH_TM_STR);
System.out.println("original cookie="+cookie);

      byte[] byteArrary = wssc.encryptData(cookie);
      String hexString = wssc.toHexStringFromByteArray(byteArrary);
System.out.println("encrypted cookie="+hexString);
      System.exit(0);

    } catch (Exception e) {
      System.err.println("Error: " + e);
      System.exit(1);
    }
  }  /* main */
}
