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
package org.onap.dcae.cdf.util.threads;

import java.util.LinkedList;
import java.util.List;

/**
 *	Various utility functions dealing with threads
 */
public class ThreadUtils {
    /**
     * Get a list of all threads.
     *
     * @return          an array of threads
     */
    public static Thread[] getAllThreads() {
	ThreadGroup rootGroup = getRootGroup();
	int noThreads = rootGroup.activeCount(); // returns an estimated count of active threads
	Thread[] threads = new Thread[noThreads + 1];
	rootGroup.enumerate(threads);
	
	while ( rootGroup.enumerate( threads, true ) == threads.length ) { // iterate if we filled up the array
	    threads = new Thread[ threads.length + noThreads ];
	}
	// remove null threads
	LinkedList<Thread> lthreads = new LinkedList<Thread>();
	for (Thread thread: threads)
	    if (thread != null)
		lthreads.push(thread);
	return lthreads.toArray(new Thread[0]);
    }

    /**
     * Get a list of all threads with a given thread name.
     *
     * @param   name    the name to look for
     * @return          an array of threads with that name
     */
    public static Thread[] getNamedThreads(final String name) {
	Thread[] allThreads = getAllThreads();
	LinkedList<Thread> lthreads = new LinkedList<Thread>();
	for (Thread thread: allThreads)
	    if (thread.getName().equals(name))
		lthreads.push(thread);

	return lthreads.toArray(new Thread[0]);
    }

    /**
     * Get the ultimate root of the threads
     *
     * @return          the root thread
     */
    public static ThreadGroup getRootGroup() {
	ThreadGroup rootGroup = Thread.currentThread( ).getThreadGroup( );
	ThreadGroup parentGroup;
	while ( ( parentGroup = rootGroup.getParent() ) != null ) {
	    rootGroup = parentGroup;
	}
	return rootGroup;
    }

    public static void main(String args[]) throws Exception {
	System.out.println("==== get Root Threads ====");
	System.out.println("Root thread = " + getRootGroup().getName());
	System.out.println("==== get All Threads ====");
	Thread[] threads = getAllThreads();
	for (int i = 0; i < threads.length; i++)
	    System.out.println("Thread No:" + i + " = " + threads[i].getName());
	System.out.println("==== getNamedThreads(main) ====");
	threads = getNamedThreads("main");
	for (int i = 0; i < threads.length; i++)
	    System.out.println("Thread No:" + i + " = " + threads[i].getName());
    }
}
