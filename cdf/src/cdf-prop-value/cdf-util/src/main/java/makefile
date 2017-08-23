
go=../../../../buildjars/gnu_getopt.jar

.SUFFIXES= .class

JAVA=	org/openecomp/dcae/cdf/util/common/Classify.java \
	org/openecomp/dcae/cdf/util/common/Tuple3.java \
	org/openecomp/dcae/cdf/util/common/AsHex.java \
	org/openecomp/dcae/cdf/util/common/G2CookieGen.java \
	org/openecomp/dcae/cdf/util/common/Compress.java \
	org/openecomp/dcae/cdf/util/common/Pair.java \
	org/openecomp/dcae/cdf/util/common/Tuple4.java \
	org/openecomp/dcae/cdf/util/common/Hostname.java \
	org/openecomp/dcae/cdf/util/common/Uid.java \
	org/openecomp/dcae/cdf/util/common/Tuple2.java \
	org/openecomp/dcae/cdf/util/common/Pid.java \
	org/openecomp/dcae/cdf/util/common/Convert.java \
	org/openecomp/dcae/cdf/util/common/Popen.java \
	org/openecomp/dcae/cdf/util/config/PropValue.java \
	org/openecomp/dcae/cdf/util/config/Configuration.java \
	org/openecomp/dcae/cdf/util/config/EncryptedConfiguration.java \
	org/openecomp/dcae/cdf/util/config/Configurable.java \
	org/openecomp/dcae/cdf/util/config/ConfigurationRegistry.java \
	org/openecomp/dcae/cdf/util/threads/TaskThread.java \
	org/openecomp/dcae/cdf/util/threads/ThreadUtils.java

CLASSES=$(JAVA:.java=.class)

all:

build: cdf-util.jar

cdf-util.jar: $(CLASSES)
	rm -f cdf-util.jar
	jar cvf cdf-util.jar $(CLASSES)

clean: 
	find . -name '*.class' -exec rm -f {} +
	rm -rf javadoc

$(CLASSES): $(JAVA)
	javac -cp $(go) $(JAVA)

javadocs:
	rm -rf javadoc
	mkdir -p javadoc
	javadoc -d javadoc -classpath $(go) $(JAVA)
