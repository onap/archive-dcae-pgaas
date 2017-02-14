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

import java.net.InetAddress;

public class Hostname {

    /** 
     * Hostname FQDN
     */
    public static String getHostName() {
        return getHostName("unknown.unknown");
    }

    /** 
     * Hostname FQDN
     */
    public static String getHostName(String def) {
        return (uname == null) ? def : hostName;
    }

    /** 
     * uname, the 1st portion of the hostname FQDN
     */
    public static String getUname() {
        return getUname("unknown");
    }

    /** 
     * uname, the 1st portion of the hostname FQDN
     */
    public static String getUname(String def) {
        return (uname == null) ? def : uname;
    }

    /**
     *	Get an IP address for this machine
     */
    public static String getLocalIP() {
	return defaultLocalIP;
    }
    /**
     *	Get an IP address for this machine
     */
    public static String getLocalIPinHex() {
	return defaultLocalIPinHex;
    }
    /**
     *	Get a host name for this machine
     */
    public static String getCanonicalHostName() {
	return defaultCanonicalHostName;
    }

    /**
     *	Value returned by getLocalIP() method
     */
    private static String	defaultLocalIP;
    private static String	defaultLocalIPinHex;
    private static String	defaultCanonicalHostName;
    private static String hostName = null;	// Hostname FQDN
    private static String uname = null;		// Hostname 1st part

    static {
	try {
	    InetAddress ia = InetAddress.getLocalHost();
	    defaultLocalIP = ia.getHostAddress();
	    byte b[] = ia.getAddress();
	    defaultLocalIPinHex = Convert.toHexString(b);
	    defaultCanonicalHostName = ia.getCanonicalHostName();
	} catch (Exception e) {
	    defaultLocalIP = "127.0.0.1";
	    defaultLocalIPinHex = "7F000001";
	    defaultCanonicalHostName = "localhost";
	}

      try {
         hostName = InetAddress.getLocalHost().getHostName();
	 String hostNameParts[] = hostName.split("\\.");
	 uname = hostNameParts[0];
      } catch (Exception ex) {
      }
      int dotInHostname = hostName.indexOf('.');
      if (dotInHostname > -1) hostName = hostName.substring(0, dotInHostname);
    }

    public static void main(String args[]) {
	System.out.println("getHostName() = '" + getHostName() + "'");
	System.out.println("getUname() = '" + getUname() + "'");
	System.out.println("getLocalIP() = '" + getLocalIP() + "'");
	System.out.println("getLocalIPinHex() = '" + getLocalIPinHex() + "'");
	System.out.println("getCanonicalHostName() = '" + getCanonicalHostName() + "'");
    }
}
