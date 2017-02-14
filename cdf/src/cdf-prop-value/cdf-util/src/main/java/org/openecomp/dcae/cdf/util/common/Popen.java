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

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public class Popen {
    public static class Results {
	public final String stdout, stderr;
	public final int exitValue;
	public Results(String so, String se, int e) {
	    stdout = so; stderr = se; exitValue = e;
	}
    }

    public static Results popen(String cmd) throws java.io.IOException, java.lang.InterruptedException {
	return popen(cmd, null);
    }

    public static Results popen(String cmd, String stdin) throws java.io.IOException, java.lang.InterruptedException {
	Process process = Runtime.getRuntime().exec(cmd);
	return proc(process, stdin);
    }

    public static Results popen(String[] args) throws java.io.IOException, java.lang.InterruptedException {
	return popen(args, null);
    }

    public static Results popen(String[] args, String stdin) throws java.io.IOException, java.lang.InterruptedException {
	Process process = Runtime.getRuntime().exec(args);
	return proc(process, stdin);
    }

    private static Results proc(Process process, String stdin) throws java.io.IOException, java.lang.InterruptedException {
	OutputStream pinput = process.getOutputStream();
	InputStream poutput = process.getInputStream();
	InputStream perror = process.getErrorStream();

	if (stdin != null)
	    pinput.write(stdin.getBytes());
	pinput.close();

	String stdout = captureStream(poutput);
	poutput.close();
	String stderr = captureStream(perror);
	perror.close();
	process.waitFor();
	//	System.out.println("stdin=\nnvvvvvvvvvvvvvvvv\n");
	//	System.out.println(stdin);
	//	System.out.println("^^^^^^^^^^^^^^^^");
	//	System.out.println("stdout=\nvvvvvvvvvvvvvvvv\n");
	//	System.out.println(stdout);
	//	System.out.println("^^^^^^^^^^^^^^^^");
	//	System.out.println("stderr=\nvvvvvvvvvvvvvvvv\n");
	//	System.out.println(stderr);
	//	System.out.println("^^^^^^^^^^^^^^^^");
	return new Results(stdout, stderr, process.exitValue());
    }

    private static String captureStream(InputStream inp) throws java.io.IOException {
	byte[] buf = new byte[8192];
	StringBuffer out = new StringBuffer();
	int b;
	while ((b = inp.read(buf)) > 0) {
	    out.append(new String(buf, 0, b));
	}
	return out.toString();
    }
}
