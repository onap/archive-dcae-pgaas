
DEVBIN=../../bin
PKG=postgresql-config
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
	rm -rf $(INS)

build:

stage: clean-stage clean-common
	mkdir -p $(INS)
	find stage ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	find common ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	chmod -R a+x $(INS)/stage/opt/app/postgresql-config/etc/*
	cp -p repackage.* $(INS)


debian: stage
	repackage -y repackage.json -b debian -d $(INS) -u
	repackage -y repackage.json -b debian -d $(INS) -u -B LATEST
	@echo debian built

upload-javadocs: 
	@echo nothing to do here

