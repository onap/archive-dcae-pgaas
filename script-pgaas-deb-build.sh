#!/bin/bash
# Create a debian package and push to remote repo

[ "$#" != "1" ] && set -- verify
phase="$1"
case $phase in
    verify|merge|release)
	echo "Running $phase job"
	;;
    *)
	echo "Unknown phase $phase"
	exit 1
	;;
esac


#
echo "============== STARTING SCRIPT TO CREATE DEBIAN FILES ================="

TIMESTAMP=$(date +%C%y%m%dT%H%M%S) 
export BUILD_NUMBER="${TIMESTAMP}"
export PATH="$PATH:${WORKSPACE}/buildtools/bin"
export NEXUS_RAW="${NEXUSPROXY}/content/sites/raw"

USER=$(xpath -q -e \
    "//servers/server[id='ecomp-raw']/username/text()" "$SETTINGS_FILE")
PASS=$(xpath -q -e \
    "//servers/server[id='ecomp-raw']/password/text()" "$SETTINGS_FILE")

# Create a netrc file for use with curl
export NETRC=$(mktemp)
echo "machine nexus.openecomp.org login ${USER} password ${PASS}" > "${NETRC}"

case "$phase" in
	verify|merge ) REPO="${NEXUS_RAW}/org.openecomp.dcae.pgaas/deb-snapshots" ;;
	release ) REPO="${NEXUS_RAW}/org.openecomp.dcae.pgaas/deb-releases" ;;
esac

export REPACKAGEDEBIANUPLOAD="set -x; curl -k --netrc-file '${NETRC}' \
    --upload-file '{0}' '${REPO}/{2}-{1}'"
export REPACKAGEDEBIANUPLOAD2="set -x; curl -k --netrc-file '${NETRC}' \
    --upload-file '{0}' '${REPO}/{2}-{4}.deb'"

case "$phase" in
	verify ) make debian-verify ;;
	merge ) make debian ;;
	release ) make debian ;;
esac

echo "================= ENDING SCRIPT TO CREATE DEBIAN FILES ================="

#echo "============= STARTING SCRIPT TO CREATE JAVADOCS FILES ================"
#make upload-javadocs
#echo "============= ENDING SCRIPT TO CREATE JAVADOCS FILES =================="
