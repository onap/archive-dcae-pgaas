#!/bin/bash
# Create a debian package and push to remote repo

if [ "$#" != "1" ]; then
    phase="verify"
else
    phase="$1"
    case $phase in
        verify|merge|release)
            echo "Running $phase job"
        ;;
        *)
            echo "Unknown phase $phase"
            exit 1
    esac
fi


#
echo "============== STARTING SCRIPT TO CREATE DEBIAN FILES ================="

export BUILD_NUMBER="${BUILD_ID}"
export PATH="$PATH:${WORKSPACE}/buildtools/bin"
export NEXUS_RAW="${NEXUSPROXY}/content/sites/raw"

USER=$(xpath -q -e \
    "//servers/server[id='ecomp-raw']/username/text()" "$SETTINGS_FILE")
PASS=$(xpath -q -e \
    "//servers/server[id='ecomp-raw']/password/text()" "$SETTINGS_FILE")

# Create a netrc file for use with curl
export NETRC=$(mktemp)
echo "machine nexus.openecomp.org login ${USER} password ${PASS}" > "${NETRC}"

if [ "$phase" == "verify" ]; then
    REPO="${NEXUS_RAW}/org.openecomp.dcae.pgaas/deb-snapshots"
else
    REPO="${NEXUS_RAW}/org.openecomp.dcae.devnull/deb-snapshots"
fi
export REPACKAGEDEBIANUPLOAD="set -x; curl -k --netrc-file '${NETRC}' \
    --upload-file '{0}' '${REPO}/{2}/{1}'"
export REPACKAGEDEBIANUPLOAD2="set -x; curl -k --netrc-file '${NETRC}' \
    --upload-file '{0}' '${REPO}/{2}/{4}-LATEST.deb'"
make debian

echo "================= ENDING SCRIPT TO CREATE DEBIAN FILES ================="

#echo "============= STARTING SCRIPT TO CREATE JAVADOCS FILES ================"
#make upload-javadocs
#echo "============= ENDING SCRIPT TO CREATE JAVADOCS FILES =================="
