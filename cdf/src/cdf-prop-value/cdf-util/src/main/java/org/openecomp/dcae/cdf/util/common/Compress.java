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

import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipOutputStream;
import java.util.zip.ZipEntry;
// import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.File;
import java.io.IOException;

public class Compress {

    /**
     * Compress a file with the gzip algorithm, sending output to outFilename.
     * Based on code at http://www.java-tips.org/java-se-tips/java.util.zip/how-to-compress-a-file-in-the-gip-format.html.
     */
    public static void gzip(String inFilename, String outFilename) throws IOException {
	String tmpFilename = outFilename + ".tmp";
	try {
	    // Create the GZIP output stream
	    GZIPOutputStream out = new GZIPOutputStream(new FileOutputStream(tmpFilename));

	    // Open the input file
	    FileInputStream in = new FileInputStream(inFilename);

	    // Transfer bytes from the input file to the GZIP output stream
	    byte[] buf = new byte[4096];
	    int len;
	    while ((len = in.read(buf)) > 0) {
		out.write(buf, 0, len);
	    }
	    in.close();

	    // Complete the GZIP file
	    out.finish();
	    out.close();
	    
	    // rename .gz.tmp to .gz
	    File target = new File(outFilename);
	    if (target.exists()) target.delete();
	    File file = new File(tmpFilename);
	    boolean result = file.renameTo(target);
	    if (!result) throw new IOException("Cannot rename " + tmpFilename + " to " + outFilename);
	} catch (IOException e) {
	    // If we can't write the gzip file, remove it and pass on the exception.
	    File f = new File(outFilename);
	    f.delete();
	    throw e;
	}
    }

    /**
     * Compress a file with the gzip algorithm, sending output to filename+".gz".
     */
    public static void gzip(String filename) throws IOException {
        gzip(filename, filename + ".gz");
    }

    /**
     * Compress a file with the zip algorithm, sending output to outFilename
     * Based on code at http://www.java-tips.org/java-se-tips/java.util.zip/how-to-compress-a-file-in-the-gip-format.html.
     */
    public static void zip(String inFilename, String outFilename) throws IOException {
	String tmpFilename = outFilename + ".tmp";
	try {
	    // Create the ZIP output stream
	    ZipOutputStream out = new ZipOutputStream(new FileOutputStream(tmpFilename));
	    ZipEntry zipEntry = new ZipEntry(inFilename);
	    out.putNextEntry(zipEntry);

	    // Open the input file
	    FileInputStream in = new FileInputStream(inFilename);

	    // Transfer bytes from the input file to the ZIP output stream
	    byte[] buf = new byte[4096];
	    int len;
	    while ((len = in.read(buf)) > 0) {
		out.write(buf, 0, len);
	    }
	    in.close();

	    // Complete the ZIP file
	    out.finish();
	    out.close();
	    
	    // rename .zip.tmp to .zip
	    File target = new File(outFilename);
	    if (target.exists()) target.delete();
	    File file = new File(tmpFilename);
	    boolean result = file.renameTo(target);
	    if (!result) throw new IOException("Cannot rename " + tmpFilename + " to " + outFilename);
	} catch (IOException e) {
	    // If we can't write the zip file, remove it and pass on the exception.
	    File f = new File(outFilename);
	    f.delete();
	    throw e;
	}
    }

    /**
     * Compress a file with the gzip algorithm, sending output to filename+".zip".
     */
    public static void zip(String filename) throws IOException {
        zip(filename, filename + ".zip");
    }

    public static void main(String args[]) throws Exception {
	if (args.length == 1) {
	    gzip(args[0]);
	    zip(args[0]);
	} else {
	    System.err.println("Usage: java Compress filename");
	}
    }
}
