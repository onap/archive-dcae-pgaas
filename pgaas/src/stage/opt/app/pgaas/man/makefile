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


.SUFFIXES: .man .1

TR2MAN = 
%.1 : %.man
        $(TR2MAN)

STAGEDIR=/dev/null
DISTPATH=/opt/app/pgaas

TRFILES := $(wildcard *.man)
MANFILES := $(patsubst %.man,%.1,$(wildcard *.man))

all: $(MANFILES)

stage: $(MANFILES)
	rm -rf $(STAGEDIR)/$(DISTPATH)/man
	mkdir -p $(STAGEDIR)/$(DISTPATH)/man
	cp -p $(MANFILES) $(STAGEDIR)/$(DISTPATH)/man

clean:
	rm -f *~

clobber: clean
	rm -f *.1

# really should not need to list each of the files individually here with how to make them

check_cluster.1: check_cluster.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
dcae_admin_db.1: dcae_admin_db.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
isrw.1: isrw.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
list_masters.1: list_masters.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
pg_ctl_promote.1: pg_ctl_promote.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
pg_ctl_restart.1: pg_ctl_restart.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
pg_ctl_start.1: pg_ctl_start.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
pg_ctl_status.1: pg_ctl_status.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
pg_ctl_stop.1: pg_ctl_stop.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
repmgrc.1: repmgrc.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
repmgrdc.1: repmgrdc.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
runpsqll.1: runpsqll.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
runpsql.1: runpsql.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
setpropvalue.1: setpropvalue.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_is_in_recovery.1: show_pg_is_in_recovery.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_activity.1: show_pg_stat_activity.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_archiver.1: show_pg_stat_archiver.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_bgwriter.1: show_pg_stat_bgwriter.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_database_conflicts.1: show_pg_stat_database_conflicts.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_database.1: show_pg_stat_database.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_statio_user_functions.1: show_pg_statio_user_functions.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_statio_user_indexes.1: show_pg_statio_user_indexes.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_statio_user_sequences.1: show_pg_statio_user_sequences.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_statio_user_tables.1: show_pg_statio_user_tables.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_user_indexes.1: show_pg_stat_user_indexes.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
show_pg_stat_user_tables.1: show_pg_stat_user_tables.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
startpsql.1: startpsql.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
update_var_run_isrw.1: update_var_run_isrw.man
	DATE=$$(date +%Y-%m-%d); sed "1s/ {{DATE}} / $$DATE /" < $< | nroff -Tlp -man > $@
