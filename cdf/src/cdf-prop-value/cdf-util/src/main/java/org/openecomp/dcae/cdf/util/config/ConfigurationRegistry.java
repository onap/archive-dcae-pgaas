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

import java.util.logging.*;
import java.lang.ref.*;

/**
 *	Class to register and notify other objects when needed.
 *	Those other objects must implement Configurable.
 */

public class ConfigurationRegistry {
	public ConfigurationRegistry() { }

	/**
	 *	The set of registered configurables
	 */
	private WeakReference<Configurable>[] configurables = new WeakReference[0];

	/**
	 *	Request callback whenever the configuration data changes
	 */
	public synchronized void registerConfigurable(Configurable element) {
		// System.out.println("adding " + element.getClass().getName() + ", length=" + Integer.toString(configurables.length));
		for (int i = 0; i < configurables.length; i++) {
			if (configurables[i].get() == element) {
				return;
			}
		}
		WeakReference<Configurable>[] nconfigurables = new WeakReference[configurables.length + 1];
		System.arraycopy(configurables, 0, nconfigurables, 0, configurables.length);
		nconfigurables[configurables.length] = new WeakReference<Configurable>(element);
		configurables = nconfigurables;
		element.reConfigure();
	}

	/**
	 *	Cancel request for callbacks when configuration changes
	 */
	public synchronized void deRegisterConfigurable(Configurable element) {
		// System.out.println("removing " + element.getClass().getName() + ", length=" + Integer.toString(configurables.length));
		for (int i = 0; i < configurables.length; i++) {
			if (configurables[i].get() == element) {
				WeakReference<Configurable>[] nconfigurables = new WeakReference[configurables.length - 1];
				if (i > 0) {
					System.arraycopy(configurables, 0, nconfigurables, 0, i);
				}
				if (i < nconfigurables.length) {
					System.arraycopy(configurables, i + 1, nconfigurables, i, nconfigurables.length - i);
				}
				configurables = nconfigurables;
				return;
			}
		}
	}

	/**
	 *	Notify all of the Configurables that they need to reConfigure.
	 */
	public void reConfigureAll() {
	    reConfigureAll(Logger.getLogger(ConfigurationRegistry.class.getName()));
	}

	/**
	 *	Notify all of the Configurables that they need to reConfigure.
	 */
	public void reConfigureAll(Logger logger) {
		// System.out.println("reConfigureAll(), length=" + Integer.toString(configurables.length));
		for (int i = 0; i < configurables.length; i++) {
			try {
				// System.out.println("reConfigureAll(), i=" + Integer.toString(i));
				WeakReference<Configurable> wc = configurables[i];
				Configurable c = (wc != null) ? wc.get() : null;
				if (c != null)
					c.reConfigure();
			} catch (Exception e) {
				WeakReference<Configurable> wc = configurables[i];
				Configurable c = (wc != null) ? wc.get() : null;
				logger.log(Level.SEVERE, "DAIS0048 Unrecoverable configuration error CNFG0005: Problem while invoking reConfigure for: " +
				    ((wc == null) ? "null" : (c == null) ? "null/null" : c.getClass().getName()) + ": " +
				    e.getMessage(), e);
			}
		}
	}

	/**
	 *	Return the number of configurables that are registered.
	 */
	public int getCount() {
	    return configurables.length;
	}
}
