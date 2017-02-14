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

import java.io.*;
import java.util.*;
import java.net.*;
import java.util.logging.*;
import org.openecomp.dcae.cdf.util.common.*;
import org.openecomp.dcae.cdf.util.threads.*;

/**
 *	Class to monitor configuration parameters and notify
 *	other objects when they change
 */

public class Configuration extends Thread implements Configurable {
	/**
	 *	Time between checks of config file in milliseconds
	 */
	private static int		INTERVAL = 30000;
	private int			interval = INTERVAL;
	/**
	 *	Minimum age of config file before loading it in milliseconds
	 */
	private static final int	MINAGE = 30000;
	private int			minage = MINAGE;
	/**
	 *	Value returned by getInstance() method
	 */
	private static Configuration	defaultInstance = new Configuration();
	/**
	 *	Value returned by getLocalIP() method
	 */
	private static String	defaultLocalIP;
	private static String	defaultLocalIPinHex;
	private static String	defaultCanonicalHostName;
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
	 *	Get a default global instance
	 */
	public static Configuration getInstance() {
		return defaultInstance;
	}
	/**
	 *	The current configuration
	 */
	private ResourceBundle	config;
	/**
	 *	Where to log when things go wrong
	 */
    private static Logger	logger = Logger.getLogger(Configuration.class.getName());
	/**
	 *	The config file to read
	 */
	private File	file;
	/**
	 *	The name of the config to read, when overriding the file.
	 */
	private String	filename;
	/**
	 *	The last modified date of the config file
	 */
	private long	curdate;
	/**
	 *	Should we stop scanning for config file updates?
	 */
	private boolean closed;
	static boolean closeAll = false;
	/**
	 *	Have we started scanning for config file updates?
	 */
	private boolean initialized;
	/**
	 *	The name of the background thread monitoring the file.
	 */
	private static String monitorThreadName = "Configuration Monitor";
	/**
	 *	How we keep track of registered Configurables.
	 */
	private ConfigurationRegistry configurationRegistry = new ConfigurationRegistry();
	/**
	 *	included file.
	 */
	private Configuration subConfig = null;
	private String subFile = null;

	public void reConfigure() {
		configurationRegistry.reConfigureAll(logger);
	}

	/**
	 *	Create an instance using the default configuration file
	 *	"configfile.properties" from the class path
	 */
	public Configuration() {
		// logger.fine("Configuration()");
	}
	/**
	 *	Create an instance using a configuration file
	 *	"FILENAME.properties" from the class path
	 */
	public Configuration(String filename) {
		// logger.fine("Configuration(" + filename + ")");
		this.filename = filename;
	}
	/**
	 *	Create an instance using a specific configuration file
	 */
	public Configuration(File file) {
		this.file = file;
		// logger.fine("Configuration(File)");
	}

	/**
	 *	Change the configuration file to use
	 */
	public void setConfig(File file) {
		this.file = file;
		curdate = 0;
		interrupt();
	}
	/**
	 * Reset the interval used for rechecking the file.
	 * @param interval
	 */
	public synchronized void setInterval(int interval) {
		this.interval = interval;
	}
	/**
	 * Reset the default interval used for rechecking the file.
	 * @param interval
	 */
	public synchronized void setDefaultInterval(int interval) {
		this.INTERVAL = interval;
	}
	/**
	 * Reset the minimum age the file must be before being reread.
	 * This is used to prevent reading the file while it is being written, say by vi.
	 * @param minage
	 */
	public synchronized void setMinage(int minage) {
		this.minage = minage;
	}
	/**
	 *	Stop checking for config changes
	 */
	public void close() {
		checkinit();
		closed = true;
		if (Thread.currentThread() == this) {
			return;
		}
		interrupt();
		try {
			join();
		} catch (Exception e) {
		}
	}
	/**
	 *	Check the config file to see if it has changed
	 */
	private synchronized void check() {
		long now = System.currentTimeMillis();
		if (logger.isLoggable(Level.FINE)) logger.fine("check(): now=" + Long.toString(now));
		try {
			long ndate = file.lastModified();
			if (logger.isLoggable(Level.FINE)) logger.fine("file=" + file + ", ndate=" + Long.toString(ndate) + ", curdate=" + Long.toString(curdate,10));
			if (ndate == curdate || (now < ndate + minage && curdate != 0)) {
				return;
			}
			if (logger.isLoggable(Level.FINE)) logger.fine("reloading file=" + file);
			FileInputStream in = new FileInputStream(file);
			config = new PropertyResourceBundle(in);
			in.close();
			try {
			    String inc = config.getString("include");
			    if ((inc != null) && !inc.equals("")) {
				subFile = inc;
				subConfig = new Configuration(subFile);
				subConfig.registerConfigurable(this);
			    }
			} catch (Exception e) {
			}

			curdate = ndate;
			configurationRegistry.reConfigureAll(logger);
			// logger.info("CNFG0006: Configuration '" + file + "' reloaded");
		} catch (Exception e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0004: Configuration file '" + file + "' inaccessible", e);
		}
	}
	/**
	 *	Make sure we're initialized and read the config file
	 *	if necessary
	 */
	public void checkinit() {
		// System.out.println("checkinit()");
		if (initialized) {
			return;
		}
		initialized = true;
		try {
			if (file == null) {
				if (filename == null)
					filename = System.getProperty("configfile", "configfile");
				// logger.info("DAIS0073 0.8.73 >>> filename=" + filename);
				if (filename.charAt(0) == '/') {
				    // logger.info("DAIS0073 0.8.73 filename has leading slash: " + filename);
				    file = new File(filename);
				} else {
				    URI uri = getClass().getClassLoader().getResource(filename + ".properties").toURI();
				    // logger.info("DAIS0073 0.8.73 uri=" + uri.toString());
				    file = new File(uri);
				}
			}
		} catch (Exception e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0003: Cannot find configuration file '" + filename + "'", e);
		}
		check();
		setDaemon(true);
		setName(monitorThreadName);
		start();
	}
	/**
	 *	Check the config file to see if it has changed
	 */
	public void run() {
		if (logger.isLoggable(Level.FINE)) logger.fine("Configuration::run()");
		while (!closed && !closeAll) {
			try {
				if (logger.isLoggable(Level.FINE)) logger.fine("sleeping " + Integer.toString(interval) + ", id=" + Long.toString(Thread.currentThread().getId()) + ", file=" + filename);
				Thread.sleep(interval);
			} catch (Exception e) {
			}
			if (logger.isLoggable(Level.FINE)) {
			    Thread currentThread = Thread.currentThread();
			    logger.fine("checking id=" + Long.toString((currentThread != null) ? currentThread.getId() : -1) + ", file=" + filename);
			}
			check();
		}
	}

	public static void wakeAllThreads() {
		try {
			Thread[] threads = ThreadCommon.getAllThreads( monitorThreadName );
			for ( Thread thread : threads )
				thread.interrupt();
		} catch (Exception e) {
		}
	}

	public static void closeAllThreads() {
		closeAll = true;
		wakeAllThreads();
	}

	/**
	 *	Forward this Configurable to the ConfigurationRegistry to be registered.
	 */
	public void registerConfigurable(Configurable element) {
	    configurationRegistry.registerConfigurable(element);
	}
	/**
	 *	Forward this Configurable to the ConfigurationRegistry to be deRegistered.
	 */
	public void deRegisterConfigurable(Configurable element) {
	    configurationRegistry.deRegisterConfigurable(element);
	}

	/**
	 *	Get a configuration parameter as a String.
	 *	If undefined, return null and log an error.
	 *	@return String
	 */
	public String getString(String name) {
		return getString(name, null, true);
	}
	/**
	 *	Get a configuration parameter as a String.
	 *	If undefined, return the specified default value.
	 *	@return String
	 */
	public String getString(String name, String deflt) {
		return getString(name, deflt, false);
	}

	public static String trimQuotes(String str) {
	    if (str == null) return null;
	    str = str.trim();
	    int len = str.length();
	    if (len < 2) return str;
	    char startChar = str.charAt(0);
	    char endChar = str.charAt(len-1);
	    boolean startDoubleQuote = startChar == '"';
	    boolean startSingleQuote = startChar == '\'';
	    boolean endDoubleQuote = endChar == '"';
	    boolean endSingleQuote = endChar == '\'';
	    if ((startDoubleQuote && endDoubleQuote) ||
		(startSingleQuote && endSingleQuote)) {
		return str.substring(1, len-1);
	    } else {
		return str;
	    }
	}

	/**
	 *	Get a configuration parameter as a String.
	 *	If undefined, return the specified default value.
	 *	If complaining, log an error.
	 *	@return String
	 */
	public String getString(String name, String deflt, boolean complain) {
		checkinit();
		try {
		    return trimQuotes(config.getString(name));
		} catch (Exception e) {
			if (subConfig != null) {
				try {
					return subConfig.getString(name, deflt, complain);
				} catch (Exception e2) {
				}
			}
			if (complain)
			    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0001: '" + filename + "': Configuration property " + name + " must be defined", e);
			return deflt;
		}
	}

	/**
	 *	Get a configuration parameter as a String encoded using URL % escapes.
	 *	If undefined, return null and log an error.
	 *	@return String
	 */
	public String getDecodedString(String name) {
		return getDecodedString(name, null, true);
	}
	/**
	 *	Get a configuration parameter as a String encoded using URL % escapes.
	 *	If undefined, return the specified default value.
	 *	@return String
	 */
	public String getDecodedString(String name, String deflt) {
		return getDecodedString(name, deflt, false);
	}
	/**
	 *	Get a configuration parameter as a String encoded using URL % escapes.
	 *	If undefined, return the specified default value.
	 *	If complaining, log an error.
	 *	@return String
	 */
	public String getDecodedString(String name, String deflt, boolean complain) {
		checkinit();
		try {
			return URLDecoder.decode(config.getString(name), "UTF-8");
		} catch (UnsupportedEncodingException e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0007: UTF-8 is not recognized as a character set encoding", e);
			return deflt;
		} catch (Exception e) {
			if (complain)
			    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0001: '" + filename + "': Configuration property " + name + " must be defined", e);
			return deflt;
		}
	}

	/**
	 *	Get a configuration parameter as a String[].
	 *	If undefined, return null and log an error.
	 *	@return String[]
	 */
	public String[] getStrings(String name) {
		return getStrings(name, null, "[ \t,]+", true);
	}
	/**
	 *	Get a configuration parameter as a String[].
	 *	If undefined, return the specified default.
	 *	@return String[]
	 */
	public String[] getStrings(String name, String[] deflt) {
		return getStrings(name, deflt, "[ \t,]+", false);
	}
	/**
	 *	Get a configuration parameter as a String[].
	 *	If undefined, return the specified default
	 *	@return String[]
	 */
	public String[] getStrings(String name, String[] deflt, String pattern, boolean complain) {
		name = getString(name, null, complain);
		if (name == null) {
			return deflt;
		}
		return name.trim().split(pattern);
	}

	/**
	 *	Get a configuration parameter as a String[], each String encoded using URL % escapes.
	 *	If undefined, return null and log an error.
	 *	@return String[]
	 */
	public String[] getDecodedStrings(String name) {
		return getDecodedStrings(name, null, "[ \t,]+", true);
	}
	/**
	 *	Get a configuration parameter as a String[], each String encoded using URL % escapes.
	 *	If undefined, return the specified default.
	 *	@return String[]
	 */
	public String[] getDecodedStrings(String name, String[] deflt) {
		return getDecodedStrings(name, deflt, "[ \t,]+", false);
	}
	/**
	 *	Get a configuration parameter as a String[], each String encoded using URL % escapes.
	 *	If undefined, return the specified default.
	 *	@return String[]
	 */
	public String[] getDecodedStrings(String name, String[] deflt, String pattern) {
		return getDecodedStrings(name, deflt, pattern, false);
	}
	/**
	 *	Get a configuration parameter as a String[], each String encoded using URL % escapes.
	 *	If undefined, return the specified default.
	 *	@return String[]
	 */
	public String[] getDecodedStrings(String name, String[] deflt, String pattern, boolean complain) {
		name = getString(name, null, complain);
		if (name == null) {
			return deflt;
		}
		String[] strs = (name.trim().split(pattern));
		try {
			for (int i = 0; i < strs.length; i++) {
				strs[i] = URLDecoder.decode(strs[i], "UTF-8");
			}
		} catch (UnsupportedEncodingException e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0007: UTF-8 is not recognized as a character set encoding", e);
		}
		return strs;
	}

	/**
	 *	Get a configuration parameter as a long.  If undefined or non-numeric, return -1 and log an error.
	 */
	public long getLong(String name) {
		return getLong(name, -1L);
	}
	/**
	 *	Get a configuration parameter as a long.  If undefined, return the specified default
	 *	If non-numeric, return the specified default and log an error.
	 */
	public long getLong(String name, long deflt) {
		String value = getString(name, null);
		if (value == null) {
			return deflt;
		}
		try {
			return Long.parseLong(value.trim());
		} catch (Exception e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0002: '" + filename + "': Configuration property " + name + " must be numeric", e);
			return deflt;
		}
	}

	/**
	 *	Get a configuration parameter as an int.  If undefined or non-numeric, return -1 and log an error.
	 */
	public int getInt(String name) {
		return getInt(name, -1);
	}
	/**
	 *	Get a configuration parameter as an int.  If undefined, return the specified default
	 *	If non-numeric, return the specified default and log an error.
	 */
	public int getInt(String name, int deflt) {
		String value = getString(name, null);
		if (value == null) {
			return deflt;
		}
		try {
			return Integer.parseInt(value.trim());
		} catch (Exception e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0002: '" + filename + "': Configuration property " + name + " must be numeric", e);
			return deflt;
		}
	}

	/**
	 *	Get a configuration parameter as an boolean.  If undefined or non-numeric, return false and log an error.
	 */
	public boolean getBoolean(String name) {
		return getBoolean(name, false);
	}
	/**
	 *	Get a configuration parameter as an boolean.  If undefined, return the specified default
	 *	If non-numeric, return the specified default and log an error.
	 */
	public boolean getBoolean(String name, boolean deflt) {
		String value = getString(name, null);
		if (value == null) {
			return deflt;
		}
		try {
			return Boolean.parseBoolean(value.trim());
		} catch (Exception e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0002: '" + filename + "': Configuration property " + name + " must be true/false", e);
			return deflt;
		}
	}

	/**
	 *	Get a configuration parameter as a double.  If undefined or non-numeric, return -1 and log an error.
	 */
	public double getDouble(String name) {
		return getDouble(name, -1);
	}
	/**
	 *	Get a configuration parameter as a double.  If undefined, return the specified default
	 *	If non-numeric, return the specified default and log an error.
	 */
	public double getDouble(String name, double deflt) {
		String value = getString(name, null);
		if (value == null) {
			return deflt;
		}
		try {
			return Double.parseDouble(value);
		} catch (Exception e) {
		    logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0002: '" + filename + "': Configuration property " + name + " must be numeric", e);
			return deflt;
		}
	}

	public Enumeration getKeys() {
		checkinit();
		return (config != null) ? config.getKeys() : null;
	}
}
