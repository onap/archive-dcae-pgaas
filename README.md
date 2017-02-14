# PostgreSQL as a Service (PGaaS) DB VM.

This package is built on top of the stock PostgreSQL and Repmgr packages.

PGaaS contains a set of configuration scripts, daemons, and administrative scripts
that allow PostgreSQL to be deployed, configured and managed by the DCAE Controller.
PGaaS may be deployed singly or in a cascaded cluster.

The running daemons provide health check and other information suitable for the
DCAE Controller and future dashboard access.


## Building the Code

To build the code, use the "make build" command.

To build the code and upload to a debian repository, use the "make debian" command.
