org.openecomp.dcae.cdf [^1]
======================

This repository contails two modules:
* `cdf-util`: a port of the support functions needed to support CdfPortValue command
* `cdf-prop-value` : contains only the CdfPortValue command

## Building

To build:
* `cd cdf-util-build; mvn package`

## Usage

Command: `/opt/cdf/bin/getpropvalue`

`/opt/cdf/bin/getpropvalue [-x] -n property -f property-file`
	Extract the named value from the given property-file (or full pathname[^2])

`/opt/cdf/bin/getpropvalue -e method [-n property] [-s salt] -v value`
	Encrypt the given property with the given name and value

`/opt/cdf/bin/getpropvalue -u value`
	Decrypt the given value, expressed as a triple METHOD:HEXSALT:HEXVAL

`/opt/cdf/bin/setencryptedvalues` (same as `/opt/cdf/bin/getpropvalue -E`)
	Encrypt all lines that look like ENCRYPTME.METHOD.name=value

## Examples

    # using config files:

    # echo ENCRYPTME.AES.input=bogus | /opt/cdf/bin/setencryptedvalues > testconfig.txt
    
    # cat testconfig.txt
    input.x=AES:353438323235:bf046d8a3e8b12fb678f5dec1e9d5743
    
    # /opt/cdf/bin/getpropvalue -x -n input -f /home/ht1659/src/cdf/testconfig.txt
    bogus
    
    # No file:
    
	# /opt/cdf/bin/getpropvalue -e AES -v bogus
    AES:34383638353831:0e699f0f818593e3adbc642efed20341
    
    # /opt/cdf/bin/getpropvalue -u AES:323937323833:8d95d8803978c4b13497b394d56a4a9c
    bogus



[^1]: Version 1.0, 24 Dec 2015

[^2]: The property-file valued currently requires a rooted (full) pathname.
