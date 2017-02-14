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
 * Classify holds various checking functions.
 */
public final class Classify {

    /**
     * isHex(ch) - is a character a hex value?
     *
     * @param ch (char)
     * @return boolean
     */
    public static boolean isHex(char ch) {
	return (ch >= '0' && ch <= '9') ||
	       (ch >= 'A' && ch <= 'F') ||
	       (ch >= 'a' && ch <= 'f');
    }

    /**
     * isValidGuid
     *
     * @param input (String)
     * @return boolean
     */

    public static boolean isValidGuid(String input) {
        // Checks if the GUID has the following format: "0f114b6f-3f1d-4c8f-a065-2a2ec3d0f522"

        if ( (input == null) || (input.length() != 36)) return false;

        for (int i=0; i < 36; i++) {
            char c = input.charAt(i);
            if ( (i==8 || i==13 || i==18 || i==23)) {
                if (c != '-') return false;
            }
            else if (!isHex(c)) return false;
        }
        return true;
    }


    /**
     * isValidClli
     *
     * @param input (String)
     * @return boolean
     */
    
    public static boolean isValidClli(String input) {
        // Checks if the CLLI only contains letters or digits.
        
        if (input == null) return false;
	int len = input.length();
        if (len == 0) return false;

        for (int i=0; i < len; i++) {
            char c = input.charAt(i);
            if (!Character.isLetterOrDigit(c)) return false;
        }
        return true;
    }


    /**
     * isValidCanonicalIpv4Address
     *
     * @param ipAddress (String)
     * @return boolean
     */
    
    public static boolean isValidCanonicalIpv4Address(String ipAddress) {

        String[] parts = ipAddress.split( "\\." );

        if ( parts.length != 4 ) {
            return false;
        }
        for ( String s : parts ) {
            try {
                int i = Integer.parseInt( s );
                if ( (i < 0) || (i > 255) ) {
                    return false;
                }
            } catch (Exception ex) {
                return false;
            }
        }

        return true;
    }
}
