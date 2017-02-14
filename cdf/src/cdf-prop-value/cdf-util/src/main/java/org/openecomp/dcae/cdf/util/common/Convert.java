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

import java.lang.Character;

/**
 * Covert holds various conversion functions.
 */
public final class Convert {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    /**
     * toHexString(String) - convert a string into its hex equivalent
     */
    public static String toHexString(String buf) {
	if (buf == null) return "";
	return toHexString(buf.getBytes());
    }

    /**
     * toHexString(byte[]) - convert a byte-string into its hex equivalent
     */
    public static String toHexString(byte[] buf) {
	if (buf == null) return "";
	char[] chars = new char[2 * buf.length];
	for (int i = 0; i < buf.length; ++i) {
	    chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
	    chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
	}
	return new String(chars);
    }

    // alternate implementation that's slightly slower
    // protected static final byte[] Hexhars = {
    //	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    // };
    // public static String encode(byte[] b) {
    //	StringBuilder s = new StringBuilder(2 * b.length);
    //	for (int i = 0; i < b.length; i++) {
    //	    int v = b[i] & 0xff;
    //	    s.append((char)Hexhars[v >> 4]);
    //	    s.append((char)Hexhars[v & 0xf]);
    //	}
    //	return s.toString();
    // }

    /**
     * Convert a hex string to its equivalent value.
     */
    public static String stringFromHex(String hexString) throws Exception {
	if (hexString == null) return "";
	return stringFromHex(hexString.toCharArray());
    }

    public static String stringFromHex(char[] hexCharArray) throws Exception {
	if (hexCharArray == null) return "";
	return new String(bytesFromHex(hexCharArray));
    }

    public static byte[] bytesFromHex(String hexString) throws Exception {
	if (hexString == null) return new byte[0];
        return bytesFromHex(hexString.toCharArray());
    }

    public static byte[] bytesFromHex(char[] hexCharArray) throws Exception {
	if (hexCharArray == null) return new byte[0];
	int len = hexCharArray.length;
	if ((len % 2) != 0) throw new Exception("Odd number of characters: '" + hexCharArray + "'");
	byte [] txtInByte = new byte [len / 2];
	int j = 0;
	for (int i = 0; i < len; i += 2) {
	    txtInByte[j++] = (byte)(((fromHexDigit(hexCharArray[i], i) << 4) | fromHexDigit(hexCharArray[i+1], i)) & 0xFF);
	}
	return txtInByte;
    }

    protected final static int fromHexDigit(char ch, int index) throws Exception {
	int digit = Character.digit(ch, 16);
	if (digit == -1) throw new Exception("Illegal hex character '" + ch + "' at index " + index);
	return digit;
    }
}
