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
 *	A thread with a queue of runnable tasks to execute in the
 *	thread
 */
public class TaskThread extends Thread	{
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread() {
	}
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread(Runnable target) {
		super(target);
	}
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread(ThreadGroup group, Runnable target) {
		super(group, target);
	}
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread(String name) {
		super(name);
	}
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread(ThreadGroup group, String name) {
		super(group, name);
	}
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread(Runnable target, String name) {
		super(target, name);
	}
	/**
	 *	Allocates a new TaskThread object.
	 */
	public TaskThread(ThreadGroup group, Runnable target, String name) {
		super(group, target, name);
	}
	/**
	 *	A queued request to be run in the TaskThread
	 */
	private static class Task	{
		public Task	next;
		public Runnable	target;
		public Task(Runnable target) {
			this.target = target;
		}
	}
	private Task	head;
	private Task	tail;
	protected boolean	closed;
	/**
	 *	Queue up a task to be executed by this thread.
	 */
	protected synchronized void queueRequest(Runnable r) {
		Task t = new Task(r);
		if (head == null) {
			head = t;
			wakeup();
		} else {
			tail.next = t;
		}
		tail = t;
	}
	/**
	 *	Mark as closed and wake up.
	 */
	protected synchronized void markClosed() {
		if (!closed) {
			closed = true;
			wakeup();
		}
	}
	/**
	 *	Wait for the next queued request.  If closed, return
	 *	null.  Relies on the default implementation of wakeup.
	 */
	protected synchronized Runnable waitNextRequest() {
		Task t;
		while ((t = head) == null && !closed) {
			try {
				wait();
			} catch (Exception e) {
			}
		}
		head = t.next;
		if (head == null) {
			tail = null;
		}
		return t.target;
	}
	/**
	 *	Get the next queued request or null if none
	 */
	protected synchronized Runnable nextRequest() {
		Task t = head;
		if (t == null) {
			return null;
		}
		head = t.next;
		if (head == null) {
			tail = null;
		}
		return t.target;
	}
	/**
	 *	Wake up the thread to process tasks.
	 *	Implementation depends on what the thread
	 *	is waiting on.  The default implementation
	 *	does a this.notify().
	 */
	protected void wakeup() {
		notify();
	}
	/**
	 *	Process any pending requests then return
	 */
	protected void processQueuedRequests() {
		Runnable r;
		while ((r = nextRequest()) != null) {
			r.run();
		}
	}
	/**
	 *	Check whether any tasks are pending
	 */
	protected boolean areTasksPending() {
		return (head != null);
	}
	/**
	 *	Wait for and process pending requests until closed
	 */
	protected void processRequestsForever() {
		Runnable r;
		while ((r = waitNextRequest()) != null) {
			r.run();
		}
	}
}
