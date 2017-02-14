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
package org.openecomp.dcae.cdf.util.threads;

/**
 *    Some functions to manipulate thread info. Based on
 *	http://nadeausoftware.com/articles/2008/04/java_tip_how_list_and_find_threads_and_thread_groups
 *	which is licensed under LGPL 2
 */

import java.lang.management.*;
// import java.util.Arrays;

public final class ThreadCommon {
    /**
     * ThreadCommon is not to be instantiated.
     */
    private ThreadCommon() { }

    private static ThreadGroup rootThreadGroup = null;

    /**
     * Get the root thread group in the thread group tree.
     * Since there is always a root thread group, this
     * method never returns null.
     *
     * @return		the root thread group
     */
    public static synchronized ThreadGroup getRootThreadGroup() {
	if ( rootThreadGroup != null )
	    return rootThreadGroup;
	ThreadGroup tg = Thread.currentThread().getThreadGroup();
	ThreadGroup ptg;
	while ( (ptg = tg.getParent()) != null )
	    tg = ptg;
	return tg;
    }

    /**
     * Get a list of all threads.  Since there is always at
     * least one thread, this method never returns null or
     * an empty array.
     *
     * @return		an array of threads
     */
    public static Thread[] getAllThreads() {
	final ThreadGroup root = getRootThreadGroup();
	final ThreadMXBean thbean = ManagementFactory.getThreadMXBean();
	int nAlloc = thbean.getThreadCount();
	int n = 0;
	Thread[] threads;
	do {
	    nAlloc *= 2;
	    threads = new Thread[ nAlloc ];
	    n = root.enumerate( threads, true );
	} while ( n == nAlloc );
	return copyOf( threads, n );
    }

    /**
     * Get the thread with the given name.  A null is returned
     * if no such thread is found.  If more than one thread has
     * the same name, the first one found is returned.
     *
     * @param	name	the thread name to search for
     * @return		the thread, or null if not found
     * @throws	NullPointerException
     * 			if the name is null
     */
    public static Thread getFirstThread( final String name ) {
	if ( name == null )
	    throw new NullPointerException( "Null name" );
	final Thread[] threads = getAllThreads();
	for ( Thread thread : threads )
	    if ( thread.getName().equals( name ) )
		return thread;
	return null;
    }

    /**
     * Get a list of all threads with a given thread name.
     *
     * @param	name	the name to look for
     * @return		an array of threads in that state
     */
    public static Thread[] getAllThreads( final String name ) {
	if ( name == null )
	    throw new NullPointerException( "Null name" );
	final Thread[] allThreads = getAllThreads();
	final Thread[] found = new Thread[allThreads.length];
	int nFound = 0;
	for ( Thread thread : allThreads )
	    if ( thread.getName().equals(name) )
		found[nFound++] = thread;
	return copyOf( found, nFound );
    }

    // return java.util.Arrays.copyOf( found, nFound );
    private static Thread[] copyOf( Thread[] threads, int n ) {
	Thread[] nthreads = new Thread[ n ];
	for (int i = 0; i < n; i++) {
	    nthreads[i] = threads[i];
	}
	return nthreads;
    }
}
