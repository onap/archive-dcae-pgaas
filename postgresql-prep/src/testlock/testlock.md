# testlock 1 "April 26 2006" "" ""
## NAME
testlock \- lock a file and run a command with the lock held
## SYNOPSIS
testlock [-v] [-t timeout] [-s] [-r exittcode] filename command args ...
## DESCRIPTION

Testlock will acquire a file lock and then execute a command while the lock is held.
If no timeout is provided, testlock will wait indefinitely until the file can be locked,
and then execute the command.
If a timeout is given, it will stop waiting after that many seconds have passed.

### Options

-t
Abort if the lock cannot be acquired after _timeout_ seconds.
If _timeout_ is 0, the lock will be totally non-blocking.

-s
Silently ignore errors with locking.
(Other errors will still be reported.)

-r exitcode
If the lock cannot be acquired, use this exit code instead of the default exit code of 99.

## AUTHOR
Tony Hansen.
