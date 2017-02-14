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
package org.openecomp.dcae.cdf;

import org.openecomp.dcae.cdf.util.config.PropValue;
import java.util.logging.Logger;
import org.openecomp.dcae.cdf.util.config.Configuration;
import java.io.InputStream;
import java.io.PrintStream;

public class CdfPropValue extends PropValue {
    public static String getCDFHOME() {
        String optCdf = System.getProperty("CDF_HOME");
        if (optCdf == null) optCdf = System.getenv("CDF_HOME");
        if (optCdf == null) optCdf = "/opt/app/cdf";
        return optCdf;
    }

    public static String getGLOBALPROPFILE() {
        String optCdfCfg = System.getProperty("CDF_CFG");
        if (optCdfCfg == null) optCdfCfg = System.getenv("CDF_CFG");
        if (optCdfCfg == null) optCdfCfg = getCDFHOME() + "/lib/cdf.cfg";
        return optCdfCfg;
    }

    public static void init() {
	PropValue.setGlobalPropFile(getGLOBALPROPFILE());
	PropValue.setEncryptionKeyProperty("Global_Title");
    }
    static {
	init();
    }

    public static void printEncryptedProperty(String method, String name, String salt, String value, String globalPropFile) {
	PropValue.printEncryptedProperty(method, name, salt, value, globalPropFile);
    }
    public static String generateEncryptedProperty(String method, String salt, String value, String globalPropFile) throws Exception {
	return PropValue.generateEncryptedProperty(method, salt, value, globalPropFile);
    }
    public static String generateEncryptedProperty(String method, String salt, String value, PropValue propValue) throws Exception {
	return PropValue.generateEncryptedProperty(method, salt, value, propValue);
    }
    public static void extractProperty(String f, String name, boolean encrypted) {
	PropValue.extractProperty(f, name, encrypted);
    }
    public static void extractProperty(String f, String name, boolean encrypted, String globalPropFile) {
	PropValue.extractProperty(f, name, encrypted, globalPropFile);
    }
    public static String decryptTriple(String triple, String globalPropFile) {
	return PropValue.decryptTriple(triple, globalPropFile);
    }
    public static String decryptTriple(String triple, PropValue propValue) {
	return PropValue.decryptTriple(triple, propValue);
    }
    public static void encryptInput(InputStream in, PrintStream out) throws Exception {
	PropValue.encryptInput(in, out);
    }
    public static void encryptInput() throws Exception {
	PropValue.encryptInput();
    }
    public static void encryptInput(String globalPropFile, InputStream sysin, PrintStream sysout) throws Exception {
	PropValue.encryptInput(globalPropFile, sysin, sysout);
    }
    public static void main(String args[]) throws Exception {
	PropValue.main(args);
    }


    public CdfPropValue(Configuration globalConfig, Logger logger) {
	super(globalConfig, logger);
    }

}
