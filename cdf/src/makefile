
DEVBIN=../../bin
PKG=cdf
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
	cd cdf-prop-value && $(MAKE) clean

build: javadocs build-java

build-java:
	cd cdf-prop-value && $(MAKE) build

javadocs:
	cd cdf-prop-value && $(MAKE) javadocs

stage: build clean-stage clean-common
	mkdir -p $(INS)
	find stage common ! -name makefile ! -name '*~' | cpio -pudmv $(INS)
	cp cdf-prop-value/cdf-prop-value/src/main/java/cdf-prop-value.jar $(INS)/stage/opt/app/cdf/lib/cdf-prop-value-1.0.0.jar
	cp cdf-prop-value/cdf-util/src/main/java/cdf-util.jar $(INS)/stage/opt/app/cdf/lib/jars/cdf-util-1.0.0.jar
	chmod a+x $(INSCOM)/*
	cp -p repackage.* $(INS)


debian: stage
	repackage -b debian $(REPACKAGEDEBIANOPTS) -d $(INS) -u
	repackage -b debian $(REPACKAGEDEBIANOPTS) -d $(INS) -u -B LATEST
	@echo debian built


upload-javadocs: javadocs
	cd cdf-prop-value && find cdf-*/src/main/java/javadoc -type f | while read f; do \
		curl -k --user "$${OPENECOMP_NEXUS_USER}:$${OPENECOMP_NEXUS_PASSWORD}" --upload-file "$$f" "$${OPENECOMP_NEXUS_JAVADOC}/org.openecomp.dcae.storage.cdf/1.0.0/$$f"; \
	done
	# OPENECOMP_NEXUS_JAVADOC https://ecomp-nexus:8443/repository/dcae-javadoc/
	# https://162.242.254.138:8443/#browse/browse/components:dcae-javadoc

