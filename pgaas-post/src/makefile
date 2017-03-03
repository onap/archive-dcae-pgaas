
DEVBIN=../../bin
PKG=pgaas-post
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
	find common ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	find stage ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	chmod a+x $(INSSTG)/opt/app/pgaas-post/bin/*
	cp -p repackage.* $(INS)


debian-verify: stage
	repackage -b debian $(REPACKAGEDEBIANOPTS) -d $(INS) 
	@echo debian verify built

debian: stage
	repackage -y repackage.json -b debian -d $(INS) -u
	# repackage -y repackage.json -b debian -d $(INS) -u -B LATEST
	@echo debian built

upload-javadocs: 
	@echo nothing to do here

