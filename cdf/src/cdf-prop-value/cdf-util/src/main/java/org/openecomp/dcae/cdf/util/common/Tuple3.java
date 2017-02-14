// -*- indent-tabs-mode: nil -*-
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

public class Tuple3<T1,T2,T3> extends Tuple2<T1,T2> {
    public Tuple3(T1 n1, T2 n2, T3 n3) {
	super(n1, n2);
	t3 = n3;
    }
    public Tuple3(Tuple3<T1,T2,T3> t) {
        super(t.t1, t.t2);
        t3 = t.t3;
    }
    public final T3 t3;
}
