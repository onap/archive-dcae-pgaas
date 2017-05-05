
DEVBIN=../../bin
PKG=postgresql-config
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
	repackage -b debian -d $(INS) -u
	repackage -b debian -d $(INS) -u -B LATEST
	@echo debian built

upload-javadocs: 
	@echo nothing to do here

