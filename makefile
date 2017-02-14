
all:

STAGEDIRS=cdf postgresql-prep postgresql-config pgaas pgaas-post 

build:
	for i in $(STAGEDIRS); do ( cd $$i/src && $(MAKE) build ) done

clean:
	for i in $(STAGEDIRS); do ( cd $$i/src && $(MAKE) clean ) done

stage:
	for i in $(STAGEDIRS); do ( cd $$i/src && $(MAKE) stage ) done

upload-javadocs:
	for i in $(STAGEDIRS); do ( cd $$i/src && $(MAKE) upload-javadocs ) done


debian:
	for i in $(STAGEDIRS); do ( cd $$i/src && $(MAKE) debian ) done

