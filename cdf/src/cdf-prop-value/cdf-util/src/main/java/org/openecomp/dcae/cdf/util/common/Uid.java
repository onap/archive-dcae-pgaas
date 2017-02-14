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
import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import org.openecomp.dcae.cdf.util.common.Popen;

public class Uid {
    /**
     * Return the uid.
     */
    public static int getUid() { return uid; }
    public static String getUidStr() { return uidStr; }

    private static int uid = -1;
    private static String uidStr = "";
    static {
	try {
	    uid = getUidFromProcSelfStatus();
	    if (uid == -1) uid = getUidFromIdU();
	    uidStr = Integer.toString(uid);
	} catch (java.io.IOException e) {
	    uid = -1;
	    uidStr = "-1";
	    System.err.println("Exception: " + e);
	} catch (Exception e) {
	    System.err.println("Exception: " + e);
	}
	
    }

    private static int getUidFromProcSelfStatus() throws java.io.IOException {
	int uid = -1;
	if (true) return -1;
	BufferedReader br = new BufferedReader(new FileReader(new File("/proc/self/status")));
	String thisLine = null;
	while ((thisLine = br.readLine()) != null) {
	    if (thisLine.startsWith("Uid:")) {
		String[] uids = thisLine.split("[: \t]+");
		if (uids.length > 1) {
		    uid = Integer.parseInt(uids[1]);
		    break;
		}
	    }
	}
	br.close();
	return uid;
    }

    private static int getUidFromIdU() throws java.io.IOException, java.lang.InterruptedException {
	Popen.Results results = Popen.popen("/usr/bin/id -u");
	uid = Integer.parseInt(results.stdout.trim());
	return uid;
    }
}
