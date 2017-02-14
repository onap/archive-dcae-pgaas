# Copyright (C) 2017 AT&T Intellectual Property. All rights reserved. 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this code except in compliance
# with the License. You may obtain a copy of the License
# at http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software  
# distributed under the License is distributed on an "AS IS" BASIS,  
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or  
# implied. See the License for the specific language governing  
# permissions and limitations under the License. 


all: testlock

TESTLOCK=./testlock

ttestlock: testlock
	@echo;echo should print usage list
	-$(TESTLOCK)
	@echo;echo should print usage list
	-$(TESTLOCK) -?
	@echo;echo should print missing lock filename
	-$(TESTLOCK) -t 0
	@echo;echo should print missing command
	-$(TESTLOCK) -t 0 /var/tmp/tl
	@echo;echo should run immediately
	$(TESTLOCK) -t 0 /var/tmp/tl /bin/echo hello
	@echo;echo grab lock, done SHOULD run after lock becomes available
	date;$(TESTLOCK) /var/tmp/tl sleep 5 & sleep 1; $(TESTLOCK) /var/tmp/tl /bin/echo done;date
	$(TESTLOCK) /var/tmp/tl true # cleanup
	@echo;echo grab lock, not waiting should NOT run
	date;$(TESTLOCK) /var/tmp/tl sleep 5 & sleep 1; $(TESTLOCK) -t 0 /var/tmp/tl /bin/echo not waiting;date
	$(TESTLOCK) /var/tmp/tl true # cleanup
	@echo;echo grab lock, echo should NOT run because lock does not become available in 4 seconds
	date;$(TESTLOCK) /var/tmp/tl sleep 5 & sleep 1; $(TESTLOCK) -t 3 /var/tmp/tl /bin/echo waiting up to 3 seconds;date
	$(TESTLOCK) /var/tmp/tl true # cleanup
	@echo;echo grab lock, echo should SILENTLY NOT run because lock does not become available in 4 seconds
	date;$(TESTLOCK) /var/tmp/tl sleep 5 & sleep 1; $(TESTLOCK) -t 3 -s /var/tmp/tl /bin/echo waiting up to 3 seconds;date
	$(TESTLOCK) /var/tmp/tl true # cleanup
	@echo;echo grab lock, echo SHOULD run after lock becomes available in 5 seconds
	date;$(TESTLOCK) /var/tmp/tl sleep 5 & sleep 1; $(TESTLOCK) -t 10 /var/tmp/tl /bin/echo waiting up to 10 seconds;date
	$(TESTLOCK) /var/tmp/tl true # cleanup

testlock: testlock.c
	gcc -o testlock testlock.c

clean:
	rm -f *~

clobber: clean
	rm -f testlock

stage: testlock
	cp -p testlock ../postgresql-prep/Linux/dist_files/opt/app/postgresql-prep/bin/
