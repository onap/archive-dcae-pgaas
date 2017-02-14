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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.PrintStream;
import java.io.IOException;
import java.util.logging.Logger;
import org.openecomp.dcae.cdf.util.config.Configuration;
import org.openecomp.dcae.cdf.util.config.EncryptedConfiguration;
import gnu.getopt.Getopt;

public class PropValue {
    private EncryptedConfiguration encryptedConfiguration;
    private String encryptionKey;

    public PropValue(Configuration globalConfig, Logger logger) {
	encryptionKey = globalConfig.getString(getEncryptionKeyProperty());
	encryptedConfiguration = new EncryptedConfiguration(encryptionKey, logger);
    }

    public String getEncryptedString(Configuration config, String name, String deflt, boolean complain) throws Exception {
	return encryptedConfiguration.getString(config, name, deflt, complain);
    }

    public String generateEncryptedProperty(String method, String salt, String value) throws Exception {
	return generateEncryptedProperty(method, salt, value, this);
    }

    public String decryptTriple(String triple) {
	return decryptTriple(triple, this);
    }

    public static void printEncryptedProperty(String method, String name, String salt, String value, String globalPropFile) {
	try {
	    if (name != null) System.out.print(name + ".x=");
	    if (globalPropFile == null) globalPropFile = getGlobalPropFile();
	    if (globalPropFile == null) throw new NullPointerException("globalPropFile not set");
	    System.out.println(generateEncryptedProperty(method, salt, value, globalPropFile));
	} catch (Exception e) {
	    System.err.println("Cannot encrypt '" + value + "', method '" + method + "' for property '" + name + "': "+ e.toString());
	}
    }

    public static String generateEncryptedProperty(String method, String salt, String value, String globalPropFile) throws Exception {
	Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	if (globalPropFile == null) globalPropFile = getGlobalPropFile();
	if (globalPropFile == null) throw new NullPointerException("globalPropFile not set");
	PropValue propValue = new PropValue(new Configuration(globalPropFile), logger);
	return generateEncryptedProperty(method, salt, value, propValue);
    }

    public static String generateEncryptedProperty(String method, String salt, String value, PropValue propValue) throws Exception {
	if (salt == null) salt = EncryptedConfiguration.generateSalt();
	return EncryptedConfiguration.encryptToTriple(method, salt, propValue.encryptionKey, value);
    }

    public static void extractProperty(String f, String name, boolean encrypted) {
	extractProperty(f, name, encrypted, null);
    }

    public static void extractProperty(String f, String name, boolean encrypted, String globalPropFile) {
	Configuration config = new Configuration(f);
	Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	if (globalPropFile == null) globalPropFile = getGlobalPropFile();
	if (globalPropFile == null) throw new NullPointerException("globalPropFile not set");
	PropValue propValue = new PropValue(new Configuration(globalPropFile), logger);
	String val = "";
	try {
	    if (encrypted)
		val = propValue.getEncryptedString(config, name, "", true);
	    else
		val = config.getString(name);
	    System.out.println(val);
	} catch (Exception e) {
	    System.err.println("Cannot extract '" + name + "' from '" + config + "': " + e.toString());
	}
    }

    public static void usage() {
	usage(null);
    }

    //    public static String decryptTriple(String triple) {
    //	return decryptTriple(triple, null);
    //    }

    public static String decryptTriple(String triple, String globalPropFile) {
	Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	if (globalPropFile == null) globalPropFile = getGlobalPropFile();
	if (globalPropFile == null) throw new NullPointerException("globalPropFile not set");
	PropValue propValue = new PropValue(new Configuration(globalPropFile), logger);
	return decryptTriple(triple, propValue);
    }

    public static String decryptTriple(String triple, PropValue propValue) {
	String ret = null;
	try {
	    ret = EncryptedConfiguration.decrypt(triple, propValue.encryptionKey);
	} catch (Exception e) {
	    System.err.println("Cannot decrypt '" + triple + "': " + e.toString());
	}
	return ret;
    }

    public static void encryptInput(InputStream in, PrintStream out) throws Exception {
	encryptInput(null, in, out);
    }
    public static void encryptInput() throws Exception {
	encryptInput(null, System.in, System.out);
    }

    private static void printEncryptedValue(Matcher m, PropValue propValue, PrintStream sysout) {
	String method = m.group(1);
	String name = m.group(2);
	String value = m.group(3);
	try {
	    sysout.println(name + ".x=" +
			   EncryptedConfiguration.encryptToTriple(method,
								  EncryptedConfiguration.generateSalt(),
								  propValue.encryptionKey, value));
	} catch (Exception e) {
	    System.err.println("Error: Cannot encrypt '" + value + "', method '" + method + "' for property '" + name + "': " + e.toString());
	}
    }

    public static void encryptInput(String globalPropFile, InputStream sysin, PrintStream sysout) throws Exception {
	String s;

	Pattern pDquote = Pattern.compile("^ENCRYPTME[.]([A-Z]*)[.]([^= \t]*)[ \t]*=[ \t]*\"([^\"]*)\"[ \t]*$");
	Pattern pSquote = Pattern.compile("^ENCRYPTME[.]([A-Z]*)[.]([^= \t]*)[ \t]*=[ \t]*'([^']*)'[ \t]*$");
	Pattern pNoWhite = Pattern.compile("^ENCRYPTME[.]([A-Z]*)[.]([^= \t]*)[ \t]*=[ \t]*([^ \t'\"]+)[ \t]*$");
//	Pattern pEncryptMe = Pattern.compile("^ENCRYPTME[.]([A-Z]*)[.]([^= \t]*)[ \t]*=");

	Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	if (globalPropFile == null) globalPropFile = getGlobalPropFile();
	if (globalPropFile == null) throw new NullPointerException("globalPropFile not set");
	PropValue propValue = new PropValue(new Configuration(globalPropFile), logger);

	BufferedReader in = new BufferedReader(new InputStreamReader(sysin));

	try {
	    while ((s = in.readLine()) != null) {
		// System.out.println("looking at '" + s + "'");
		Matcher mDquote = pDquote.matcher(s);
		Matcher mSquote = pSquote.matcher(s);
		Matcher mNoWhite = pNoWhite.matcher(s);
//		Matcher mEncryptMe = pNoWhite.matcher(s);
		if (mDquote.matches()) {
		    printEncryptedValue(mDquote, propValue, sysout);
		} else if (mSquote.matches()) {
		    printEncryptedValue(mSquote, propValue, sysout);
		} else if (mNoWhite.matches()) {
		    printEncryptedValue(mNoWhite, propValue, sysout);
		} else if (s.startsWith("ENCRYPTME")) {
		    throw new Exception("Bad value to encrypt: '" + s + "'");
		} else {
		    // System.out.println("printing the line: '" + s + "'");
		    sysout.println(s);
		}
	    }
	} catch (IOException e) {
	    System.err.println("Error: Cannot read from stdin: " + e.toString());
	} catch (Exception e) {
	    throw e;
	}
    }

    public static void usage(String msg) {
	if (msg != null) System.err.println(msg);
	System.err.println("Usage: java PropValue [-x] -n property -f property-file");
	System.err.println("\tExtract the named value from the given property-file (or full pathname)");
	System.err.println("Usage: java PropValue -e method [-n property] [-s salt] -v value");
	System.err.println("\tEncrypt the given property with the given name and value");
	System.err.println("Usage: java PropValue -E");
	System.err.println("\tEncrypt all lines that look like ENCRYPTME.METHOD.name=value");
	System.err.println("Usage: java PropValue -u value");
	System.err.println("\tDecrypt the given value, expressed as a triple METHOD:HEXSALT:HEXVAL");
	System.exit(1);
    }

    public static void setGlobalPropFile(String g) { sGlobalPropFile = g; }
    public static String getGlobalPropFile() { return sGlobalPropFile; }
    private static String sGlobalPropFile = null;

    public static void setEncryptionKeyProperty(String e) { encryptionKeyProperty = e; }
    public static String getEncryptionKeyProperty() { return encryptionKeyProperty; }
    private static String encryptionKeyProperty = "Global_Title";

    public static void main(String args[]) throws Exception {
	Getopt g = new Getopt( "PropValue", args, "e:Ef:G:n:s:u:v:x" );
	String propfile = null, name = null, method = null, value = null, unencrypt = null;
	String globalPropFile = getGlobalPropFile();
	boolean useDecryption = false, encryptStdin = false;
	String salt = null;
	int c;

	while ((c = g.getopt()) != -1) {
	    switch (c) {
		case 'e': method = g.getOptarg(); break;
	        case 'E': encryptStdin = true; break;
		case 'f': propfile = g.getOptarg(); break;
		case 'G': globalPropFile = g.getOptarg(); break;
		case 'n': name = g.getOptarg(); break;
		case 's': salt = g.getOptarg(); break;
	        case 'u': unencrypt = g.getOptarg(); break;
		case 'v': value = g.getOptarg(); break;
		case 'x': useDecryption = true; break;
		case '?': usage(); break;
	    }
	}
	if (encryptStdin) {
	    if (name != null || propfile != null || method != null || value != null) usage("cannot use -E with other options");
	    encryptInput(System.in, System.out);
	} else if (unencrypt == null) {
	    if (method != null) {
		if (value == null) usage("-v required");
		printEncryptedProperty(method, name, salt, value, globalPropFile);
	    } else {
		if (name == null) usage("-n is required");
		if (propfile == null) usage("-f is required");
		extractProperty(propfile, name, useDecryption, globalPropFile);
	    }
	} else {
	    System.out.println(decryptTriple(unencrypt, globalPropFile));
	}
    }
}
