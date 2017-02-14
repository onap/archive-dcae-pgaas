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

public class AsHex
{
    public static String asHex(byte[] data, int offset, int length, String sep) {
        return asHex(data, offset, length, true);
    }
    public static String asHex(byte[] data, String sep) {
        return asHex(data, 0, data.length, sep);
    }
    public static String asHex(byte[] data, int offset, int length) {
        return asHex(data, offset, length, " ");
    }
    public static String asHex(byte[] data) {
        return asHex(data, 0, data.length);
    }

    public static String asHex(String data) {
        return asHex(data.getBytes());
    }

    static private int asHexBlockLength = 16;
    public static void setAsHexBlockLength(int n) { asHexBlockLength = n; }
    public static int getAsHexBlockLength() { return asHexBlockLength; }

    private final static char[] hexdigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * return a byte buf as a hex string
     */
    public static String asHex(byte[] buf, int offset, int length, boolean addFinalNL) {
        StringBuilder ret = new StringBuilder();
        return asHex(ret, buf, offset, length, addFinalNL).toString();
    }

    /**
     * Return a byte buf as hex into the provided StringBuilder.
     */
    public static StringBuilder asHex(StringBuilder ret, byte[] buf, int offset, int length, boolean addFinalNL) {
        final int blockLength = asHexBlockLength;
        for (int o = 0; o < length; o += blockLength) {
            int iend = (o + blockLength < length) ? (o + blockLength) : length;
            int pend = o + blockLength;
            for (int i = o; i < iend; i++) {
                int b = (int)(buf[i+offset] & 0xFF);
                ret.append(hexdigits[b/16]);
                ret.append(hexdigits[b%16]);
            }
            for (int i = iend; i < pend; i++) {
                ret.append("  ");
            }
            ret.append("  ");
            for (int i = o; i < iend; i++) {
                byte b = buf[i+offset];
                int ib = (int)(b & 0xFF);
                if ((ib >= 0x20) && (ib < 0x7f)) ret.append((char)b);
                else ret.append('.');
            }
            if (iend < length) ret.append('\n');
        }
        if (addFinalNL && (length%blockLength != 0)) ret.append('\n');
        return ret;
    }

    /**
     * Return a byte buf as hex with a maximum number of lines.
     */
    public static String asHexWithMaxLines(byte[] buf, int offset, int length, int maxLines, boolean addFinalNL) {
        StringBuilder ret = new StringBuilder();
        return asHexWithMaxLines(ret, buf, offset, length, maxLines, addFinalNL).toString();
    }

    /**
     * Return a byte buf as hex into the provided StringBuilder with a maximum number of lines.
     */
    public static StringBuilder asHexWithMaxLines(StringBuilder ret, byte[] buf, int offset, int length, int maxLines, boolean addFinalNL) {
        int bytesToPrint = length - offset;
        if (maxLines < 1) maxLines = 1;
        int maxBytesToPrint = maxLines * asHexBlockLength;
        if (bytesToPrint <= maxBytesToPrint) {
            return asHex(ret, buf, offset, length, addFinalNL);
        } else {
            if (bytesToPrint > maxBytesToPrint) bytesToPrint = maxBytesToPrint;
            asHex(ret, buf, offset, offset + bytesToPrint, false);
            ret.append("  ....");
            if (addFinalNL) ret.append("\n");
            return ret;
            // return asHex(ret, buf, length - halfBytesToPrint, length, addFinalNL);
        }
    }

    // Convert a hex string back to a byte array.
    // This assumes that there is no whitespace within the string.
    //    public static byte[] fromHex(String hexStr) {
    //        byte[] bts = new byte[hexStr.length() / 2];
    //        for (int i = 0; i < bts.length; i++) {
    //            bts[i] = (byte) Integer.parseInt(hexStr.substring(2*i, 2*i+2), 16);
    //        }
    //        return bts;
    //    }
}
