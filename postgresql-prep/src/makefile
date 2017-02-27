
DEVBIN=../../bin
PKG=postgresql-prep
REPACKAGESWMOPTS=
REPACKAGEDEBIANOPTS=

INS=	../install
INSSTG=	$(INS)/stage
INSCOM=	$(INS)/common

all:

clean-stage:
	rm -rf $(INSSTG)

clean-common:
	rm -rf $(INSCOM)

clean:
	rm -rf $(INS) testlock/testlock

testlock/testlock:
	cd testlock && make testlock

build: testlock/testlock

stage: clean-stage clean-common testlock/testlock
	mkdir -p $(INS)
	find stage ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	find common ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	cp -p testlock/testlock $(INSSTG)/opt/app/postgresql-prep/bin/testlock
	chmod a+x $(INSSTG)/opt/app/postgresql-prep/bin/*
	cp -p repackage.* $(INS)


debian-verify: stage
	repackage -b debian $(REPACKAGEDEBIANOPTS) -d $(INS) 
	@echo debian verify built

debian: stage
	repackage -y repackage.json -b debian -d $(INS) -u
	repackage -y repackage.json -b debian -d $(INS) -u -B LATEST
	@echo debian built

upload-javadocs: 
	@echo nothing to do here

