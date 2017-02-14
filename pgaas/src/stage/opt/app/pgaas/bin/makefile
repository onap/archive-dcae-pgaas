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


all:

test:
	sudo -u postgres ./dcae_admin_db.py configurationChanged in.json

STAGEDIR=/dev/null
DISTPATH=/opt/app/pgaas

PYFILES= dcae_admin_db.py 
SHFILES= check_cluster isrw list_masters \
	pg_ctl_promote pg_ctl_restart pg_ctl_start pg_ctl_status pg_ctl_stop repmgrc repmgrdc \
	runpsql runpsqll startpsql setpropvalue show_pg_is_in_recovery show_pg_stat_activity show_pg_stat_archiver show_pg_stat_bgwriter \
	show_pg_stat_database show_pg_stat_database_conflicts show_pg_statio_user_functions show_pg_statio_user_indexes \
	show_pg_statio_user_sequences show_pg_statio_user_tables show_pg_stat_user_indexes show_pg_stat_user_tables \
	update_var_run_isrw

stage:
	rm -rf $(STAGEDIR)/$(DISTPATH)/bin
	mkdir -p $(STAGEDIR)/$(DISTPATH)/bin
	for i in *; do \
	    case $$i in \
		*.py ) \
		    j=`basename $$i .py`; \
		    cp $$i $(STAGEDIR)/$(DISTPATH)/bin/$$j; \
		    chmod a+x $(STAGEDIR)/$(DISTPATH)/bin/$$j; \
		    ;; \
		makefile | *~ ) ;; \
		* ) \
		    cp $$i $(STAGEDIR)/$(DISTPATH)/bin/$$i; \
		    chmod a+x $(STAGEDIR)/$(DISTPATH)/bin/$$i; \
		    ;; \
	    esac; \
	done
