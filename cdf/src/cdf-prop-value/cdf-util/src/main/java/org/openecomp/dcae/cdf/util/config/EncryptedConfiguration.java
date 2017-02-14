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
package org.openecomp.dcae.cdf.util.config;

import java.util.logging.*;
// import java.lang.ref.*;
import org.openecomp.dcae.cdf.util.common.*;
import gnu.getopt.Getopt;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/**
 *	Class to manage encrypted configuration values.
 */

public class EncryptedConfiguration {
    /**
     *	Our secret key
     */
    private String encryptionKey;

    /**
     *	Where to log when things go wrong
     */
    private Logger logger;

    public EncryptedConfiguration(String key, Logger logger) {
	encryptionKey = key.trim();
	this.logger = logger;
    }

    /**
     * Retrieve an encrypted string from the given configuration.
     * The name will have ".x" appended to it.
     * Decoded from hex, it will be "method:hexsalt:hexvalue".
     * The format of the value will be in hex.
     * Method will be "r" to begin with, for "rc4".
     */
    public String getString(Configuration config, String name, String deflt, boolean complain) throws Exception {
        return getString(config, name, deflt, complain, encryptionKey);
    }

    /**
     * Retrieve an encrypted string from the given configuration.
     * The name will have ".x" appended to it.
     * Decoded from hex, it will be "method:hexsalt:hexvalue".
     * The format of the value will be in hex.
     * Method will be "r" to begin with, for "rc4".
     */
    public String getString(Configuration config, String name, String deflt, boolean complain, String key) throws Exception {
	String str = config.getString(name + ".x", null, complain);
	if (str == null) {
	    return deflt;
	}
	return decrypt(str, key);
    }

    /**
     * Decrypt a string in 'method:hexsalt:hexvalue' format.
     */
    public static String decrypt(String triple, String key) throws Exception {
	String[] strParts = triple.trim().split(":");
	if (strParts.length != 3) throw new Exception("Encrypted value must look like 'x:y:z'");
	return decrypt(strParts[0], Convert.stringFromHex(strParts[1]), key, Convert.bytesFromHex(strParts[2]));
    }

    /**
     * Decrypt a string 'method:hexsalt:hexvalue' format.
     */
    public static String decrypt(String method, String salt, String key, byte[] bvalue) throws Exception {
	/* if (false) {
	    System.out.println("method length=" + method.length()); System.out.println(AsHex.asHex(method));
	    System.out.println("salt length=" + salt.length()); System.out.println(AsHex.asHex(salt));
	    System.out.println("key length=" + key.length()); System.out.println(AsHex.asHex(key));
	    System.out.println("bvalue length=" + bvalue.length); System.out.println(AsHex.asHex(bvalue));
	    } */
	byte[] secretKey = runDigest(salt + "." + key);

	SecretKeySpec skeySpec = new SecretKeySpec(secretKey, method);

	Cipher cipher = Cipher.getInstance(method);	// "AES"
	cipher.init(Cipher.DECRYPT_MODE, skeySpec);

	byte[] decrypted = cipher.doFinal(bvalue);
	return new String(decrypted);
    }

    /**
     * Encrypt a string using the given method, salt and key.
     */
    public static byte[] encrypt(String method, String salt, String key, String value) throws Exception {
	byte[] bvalue = value.getBytes();
	byte[] secretKey = runDigest(salt + "." + key);

	SecretKeySpec skeySpec = new SecretKeySpec(secretKey, method);

	Cipher cipher = Cipher.getInstance(method);	// "AES"
	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

	byte[] encrypted = cipher.doFinal(bvalue);
	return encrypted;
    }

    /**
     * Prepare a secret key by running a digest on it.
     */
    private static byte[] runDigest(String text) throws Exception {
	MessageDigest md = MessageDigest.getInstance("MD5");
	md.reset();
	md.update(text.getBytes(), 0, text.length());
	return md.digest();
    }

    /**
     * Encrypt a string using the given method, salt and key, and return it as a hex-formated triple.
     */
    public static String encryptToTriple(String method, String salt, String key, String value) throws Exception {
	StringBuilder sb = new StringBuilder(method);
	sb.append(':').append(Convert.toHexString(salt))
	  .append(':').append(Convert.toHexString(encrypt(method, salt, key, value)));
	return sb.toString();
    }

    /**
     * Create a value that can be used as a salt.
     */
    public static String generateSalt() {
	return Long.toString(System.currentTimeMillis() % 1000) + Pid.getPidStr();
    }

    public static void usage() {
	usage(null);
    }

    public static void usage(String msg) {
	if (msg != null) System.out.println(msg);
	System.out.println("Usage: java EncryptedConfiguration -D triple -k key\n" +
	    "java EncryptedConfiguration -d string -m method [-s salt | -S] -k key\n" +
	    "java EncryptedConfiguration -e string -m method [-s salt | -S] -k key\n" +
	    "-D\tdecrypt x:y:z triple\n" +
	    "-d\tdecrypt string (in hex)\n" +
	    "-e\tencrypt string\n" +
	    "-S\tgenerate a salt\n"
	    );
	System.exit(1);
    }

    public static void main(String args[]) throws Exception {
	Getopt g = new Getopt( "EncryptedConfiguration", args, "s:Sk:m:e:d:D:?" );

	int c, verbosity = 0;
	String salt = null, key = null, method = null, encStr = null, decStr = null, triple = null;
	boolean genSalt = false;

	while ((c = g.getopt()) != -1) {
	    switch (c) {
		case 's': salt = g.getOptarg(); break;
	        case 'S': genSalt = true; break;
		case 'k': key = g.getOptarg(); break;
		case 'm': method = g.getOptarg(); break;
		case 'e': encStr = g.getOptarg(); break;
		case 'd': decStr = g.getOptarg(); break;
		case 'D': triple = g.getOptarg(); break;
		case '?': usage(); break;
	    }
	}

	if (triple == null) {
	    if ((salt == null) && !genSalt) usage("one of -s or -S must be specified");
	    if ((salt != null) && genSalt) usage("only one of -s or -S must be specified");
	    if (key == null) usage("-k must be specified");
	    if (method == null) usage("-m must be specified");
	    if ((encStr == null) && (decStr == null)) usage("one of -d or -e must be specified");
	    if ((encStr != null) && (decStr != null)) usage("only one of -d or -e may be specified");
	    if (genSalt) salt = generateSalt();
	    if (encStr != null)
		System.out.println(encryptToTriple(method, salt, key, encStr));
	    if (decStr != null)
		System.out.println(decrypt(method, salt, key, Convert.bytesFromHex(decStr)));
	} else {
	    if (key == null) usage("-k not specified");
	    System.out.println(decrypt(triple, key));
	}

	// http://forums.sun.com/thread.jspa?threadID=5290983
	// try {
	//     String message = "Strong Versus Unlimited Strength Cryptography";
	//     SecretKeySpec skeySpec = new SecretKeySpec("0123456789ABCDEF".getBytes(), "AES"); //AES-128

	//     Cipher cipher = Cipher.getInstance("AES");	// "AES/ECB/NoPadding"
	//     cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

	//     byte[] encrypted = cipher.doFinal(message.getBytes());
	//     System.out.println("encrypted string: " + encrypted); //storing into MySQL DB
	//     System.out.println("in hex: '" + Convert.toHexString(encrypted) + "'");

	//     cipher.init(Cipher.DECRYPT_MODE, skeySpec);
	//     byte[] original = cipher.doFinal(encrypted);
	//     String originalString = new String(original);
	//     System.out.println("Original string: " + originalString);
	// } catch (Exception e) {
	//     System.err.println("Exception caught: " + e.toString());
	// }
    }
}
