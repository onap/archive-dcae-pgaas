
DEVBIN=../../bin
PKG=pgaas
REPACKAGESWMOPTS=
REPACKAGEDEBIANOPTS=

INS=	../install
INSSTG=	$(INS)/stage
INSCOM=	$(INS)/common
KEEP=

all:

clean-stage:
	rm -rf $(INSSTG)

clean-common:
	rm -rf $(INSCOM)

clean-ins: clean-stage clean-common
	rm -rf $(INS)

clean: clean-ins
	rm -rf *~

build:

stage: clean-stage
	cd stage/opt/app/pgaas && $(MAKE) stage STAGEDIR=../../../../$(INSSTG)
	find common ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	cp -p repackage.* $(INS)


debian: stage
	repackage -b debian $(REPACKAGEDEBIANOPTS) -d $(INS) -u
	repackage -b debian $(REPACKAGEDEBIANOPTS) -d $(INS) -u -B LATEST
	@echo debian built

upload-javadocs: 
	@echo nothing to do here

