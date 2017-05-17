#!/usr/bin/python3
# -*- indent-tabs-mode: nil -*-
# Copyright (C) 2017 AT&T Intellectual Property. All rights reserved. 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this code except in compliance
# with the License. You may obtain a copy of the License
# at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.


"""

NAME
    dcae_admin_db.py - given a database description json file, update the current VM accordingly

USAGE
    dcae_admin_db.py [options] configurationChanged json-file
    dcae_admin_db.py [options] suspend
    dcae_admin_db.py [options] resume
    dcae_admin_db.py [options] test

    options:

        -H / --dbhost= - host name, defaults to CFG['dcae_admin_db_hostname']
        -d / --dbdir= - database directory path, defaults to CFG['db_directory']
        -c / --dbconf= - database configuration path, defaults to CFG['db_configuration']
        -D / --dbname= - database name, defaults to CFG['dcae_admin_db_databasename']
        -U / --user= - user to login as, defaults to CFG['dcae_admin_db_username']
        -P / --password= - password for user, defaults to CFG['dcae_admin_db_password']
        -B / --bindir= - postgresql bin directory, defaults to CFG['pg_bin_directory']
        -i / --ignorefile= - skip configuration if this file is present, defaults to CFG['skip_configuration_file']
        -n / --nocreate - do not create the databases / users
        -I / --ignoredb - ignore current state of database
        -R / --remove - remove old databases / users
        -J / --jsontop= - top of json tree, as in \"['pgaas']\"
        -e / --errors= - where to redirect error output, defaults to CFG['dcae_admin_db_errors_file'] then stderr
        -t / --trace= - where to redirect trace output, defaults to CFG['dcae_admin_db_trace_file'] then stderr
        -v / --verbose - verbose, defaults to CFG['dcae_admin_db_verbosity']

DESCRIPTION
    This program is intended to be executed by the DCAE controller manager.

When creating a database and set of users, execute the equivalent of this:

    CREATE USER tstdb_admin  WITH PASSWORD 'tst';
    CREATE USER tstdb_user   WITH PASSWORD 'tst';
    CREATE USER tstdb_viewer WITH PASSWORD 'tst';

    CREATE ROLE testdb_common_user_role;
    CREATE ROLE testdb_common_viewer_role;

    CREATE DATABASE testdb with owner tstdb_admin;

    \connect testdb

    REVOKE ALL on DATABASE testdb FROM testdb_common_viewer_role;
    REVOKE ALL on DATABASE testdb FROM testdb_common_user_role;
    REVOKE ALL on DATABASE testdb FROM tstdb_user;
    REVOKE ALL on DATABASE testdb FROM tstdb_viewer;

    GRANT testdb_common_viewer_role TO testdb_common_user_role; /* user can do everything viewer can */
    GRANT testdb_common_user_role  TO tstdb_admin; /* admin can do everything user and viewer can */

    GRANT CONNECT ON DATABASE testdb TO testdb_common_viewer_role; /* viewer, user, admin can connect */

    CREATE SCHEMA testdb_db_common AUTHORIZATION tstdb_admin; /* create a schema we can optionally use */

    ALTER ROLE tstdb_admin               IN DATABASE testdb SET search_path = public, testdb_db_common; /* search_path is not inherited, so set it here */
    ALTER ROLE testdb_common_user_role   IN DATABASE testdb SET search_path = public, testdb_db_common; /* search_path is not inherited, so set it here */
    ALTER ROLE testdb_common_viewer_role IN DATABASE testdb SET search_path = public, testdb_db_common; /* search_path is not inherited, so set it here */

    GRANT USAGE  ON SCHEMA testdb_db_common TO testdb_common_viewer_role;  /* viewer,user can select from schema */
    GRANT CREATE ON SCHEMA testdb_db_common TO tstdb_admin;  /* admin can create on schema */

    ALTER DEFAULT PRIVILEGES FOR ROLE tstdb_admin GRANT SELECT ON TABLES TO testdb_common_viewer_role;                  /* viewer, user, admin can select on tables */
    ALTER DEFAULT PRIVILEGES FOR ROLE tstdb_admin GRANT INSERT, UPDATE, DELETE, TRUNCATE ON TABLES TO testdb_common_user_role; /* user, admin can ins/upd/del/tru on tables */
    ALTER DEFAULT PRIVILEGES FOR ROLE tstdb_admin GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO testdb_common_user_role;         /* user, admin can update on sequences */

    GRANT TEMP ON DATABASE testdb TO testdb_common_user_role; /* user, admin can create temp tables */

    GRANT testdb_common_user_role TO tstdb_user;
    GRANT testdb_common_viewer_role TO tstdb_viewer;
    ALTER ROLE tstdb_user   IN DATABASE testdb SET search_path = public, testdb_db_common; /* search_path is not inherited, so set it here */
    ALTER ROLE tstdb_viewer IN DATABASE testdb SET search_path = public, testdb_db_common; /* search_path is not inherited, so set it here */

"""

import getopt
import psycopg2
import sys
import re
import subprocess
import json
import os
import time

sys.path.append("/opt/app/pgaas/lib")
import CommonLogger

verbose = 0
quiet = False
errorOutput = sys.stderr
traceOutput = sys.stderr
errorLogger = debugLogger = auditLogger = metricsLogger = None

def usage(msg = None):
    """
    Print a usage message and exit
    """
    sys.stdout = sys.stderr
    if msg != None:
        print(msg)
    print("Usage:")
    print("dcae_admin_db.py [options] configurationChanged json-file")
    print("dcae_admin_db.py [options] suspend")
    print("dcae_admin_db.py [options] resume")
    print("dcae_admin_db.py [options] test")
    print("dcae_admin_db.py [options] newdb dbname admin-pswd user-pswd viewer-pswd")
    print("")
    print("options:")
    print("-H / --dbhost= - host name, defaults to CFG['dcae_admin_db_hostname']")
    print("-d / --dbdir= - database directory path, defaults to CFG['db_directory']")
    print("-c / --dbconf= - database directory path, defaults to CFG['db_configuration']")
    print("-D / --dbname= - database name, defaults to CFG['dcae_admin_db_databasename']")
    print("-n / --nocreate - do not create the databases / users")
    print("-I / --ignoredb - ignore current state of database")
    print("-U / --user= - user to login as, defaults to CFG['dcae_admin_db_username']")
    print("-P / --password= - password for user, defaults to CFG['dcae_admin_db_password']")
    print("-B / --bindir= - postgresql bin directory, defaults to CFG['pg_bin_directory']")
    print("-i / --ignorefile= - skip configuration if this file is present, defaults to CFG['skip_configuration_file']")
    print("-R / --remove - remove old databases / users")
    print("-J / --jsontop= - top of json tree, as in \"['pgaas']\"")
    print("-l / --logcfg= - ECOMP DCAE Common Logging configuration file")
    print("-e / --errors= - where to redirect error output, defaults to CFG['dcae_admin_db_errors_file'] then stderr")
    print("-t / --trace= - where to redirect trace output, defaults to CFG['dcae_admin_db_trace_file'] then stderr")
    print("-v - verbose")
    sys.exit(2)

def checkOption(options, name, propname, optletter, encrypted=False, cdfPropname = None):
    """
    Check if the specified option exists. If not, grab it from the configuration file.
    Complain if it still does not exist.
    """
    if name not in options:
        ret = getPgaasPropValue(propname, encrypted=encrypted, dflt=None, skipComplaining=True)
        if ret is None and cdfPropname is not None:
            ret = getCdfPropValue(cdfPropname, encrypted=encrypted)
        options[name] = ret
    requireOption("either %s or config[%s]" % (optletter, propname), options[name])

def reviewOpts():
    """
    Parse the options passed to the command, and return them in the dictionary
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "B:c:D:d:e:H:IJ:l:nP:Rt:U:hv?",
                                   [ "dbhost=", "dbdir=", "dbconf=",
                                     "dbname=", "dbuser=", "dbpassword=",
                                     "bindir=", "errors=", "trace=", "logcfg=",
                                     "nocreate", "ignoredb", "remove", "ignorefile=",
                                     "jsontop=",
                                     "help", "verbose"])
    except getopt.GetoptError as err:
        usage(str(err))

    propVerbosity = getPgaasPropValue("dcae_admin_db_verbosity", dflt='0')
    if propVerbosity is not None:
        global verbose
        verbose = int(propVerbosity)
    retOptions = { }
    ignoreFile = getPgaasPropValue("skip_configuration_file", dflt=None)
    for o, a in opts:
        if o in ("-v", "--verbose"):
            # global verbose
            verbose += 1
        elif o in ("-c", "--dbconf"):
            retOptions["dbconf"] = a
        elif o in ("-H", "--dbhost"):
            retOptions["dbhost"] = a
        elif o in ("-d", "--dbdir"):
            retOptions["dbdir"] = a
        elif o in ("-D", "--dbname"):
            retOptions["dbname"] = a
        elif o in ("-U", "--dbuser"):
            retOptions["dbuser"] = a
        elif o in ("-P", "--dbpassword"):
            retOptions["dbpassword"] = a
        elif o in ("-B", "--bindir"):
            retOptions["bindir"] = a
        elif o in ("-n", "--nocreate"):
            retOptions["nocreate"] = True
        elif o in ("-I", "--ignoredb"):
            retOptions["ignoredb"] = True
        elif o in ("-R", "--remove"):
            retOptions["noremove"] = True
        elif o in ("-J", "--jsontop"):
            retOptions["jsontop"] = a
        elif o in ("-l", "--logcfg"):
            retOptions["logcfg"] = a
        elif o in ("-e", "--errors"):
            retOptions["errors"] = a
        elif o in ("-i", "--ignorefile"):
            ignoreFile = a
        elif o in ("-t", "--trace"):
            retOptions["trace"] = a
        elif o in ("-h", "--help"):
            usage()
        else:
            usage("unhandled option: %s" % o)
    if "errors" not in retOptions:
        retOptions["errors"] = getPgaasPropValue("dcae_admin_db_errors_file")
    if "errors" in retOptions and retOptions["errors"] is not None:
        try:
            errorOutput = open(retOptions["errors"], "a")
        except Exception as e:
            die("Cannot open errors file '%s': %s" % (retOptions["errors"], e))
    if ignoreFile is not None:
        trace("checking to see if skip_configuration_file(%s) exists" % ignoreFile)
        retOptions["ignorefile"] = "yes" if os.path.isfile(ignoreFile) else "no"
        trace("ignorefile=%s" % retOptions["ignorefile"])
    else:
        retOptions["ignorefile"] = None
    if "trace" not in retOptions:
        retOptions["trace"] = getPgaasPropValue("dcae_admin_db_trace_file")
    if "trace" in retOptions and retOptions["trace"] is not None:
        try:
            traceOutput = open(retOptions["trace"], "a")
        except Exception as e:
            die("Cannot open trace file '%s': %s" % (retOptions["trace"], e))
    if "logcfg" not in retOptions:
        retOptions["logcfg"] = getPgaasPropValue("dcae_admin_db_common_logger_config")
    if "logcfg" in retOptions and retOptions["logcfg"] is not None:
        logcfg = retOptions["logcfg"]
        import uuid
        instanceUUID = uuid.uuid1()
        serviceName = "DCAE/pgaas"
        # print(">>>>>>>>>>>>>>>> using common logger. UUID=%s, serviceName=%s, cfg=%s" % (instanceUUID, serviceName, logcfg))
        global errorLogger, debugLogger, auditLogger, metricsLogger
        errorLogger = CommonLogger.CommonLogger(logcfg, "error", instanceUUID=instanceUUID, serviceName=serviceName)
        debugLogger = CommonLogger.CommonLogger(logcfg, "debug", instanceUUID=instanceUUID, serviceName=serviceName)
        auditLogger = CommonLogger.CommonLogger(logcfg, "audit", instanceUUID=instanceUUID, serviceName=serviceName)
        metricsLogger = CommonLogger.CommonLogger(logcfg, "metrics", instanceUUID=instanceUUID, serviceName=serviceName)
        auditLogger.info("using common logger. UUID=%s, serviceName=%s, cfg=%s" % (instanceUUID, serviceName, logcfg))

    checkOption(retOptions, "dbname", "dcae_admin_db_databasename", "-D")
    checkOption(retOptions, "dbuser", "dcae_admin_db_username", "-U")
    checkOption(retOptions, "dbpassword", "dcae_admin_db_password", "-P", encrypted=True, cdfPropname="postgres")
    checkOption(retOptions, "dbhost", "dcae_admin_db_hostname", "-H")
    checkOption(retOptions, "dbdir", "db_directory", "-d")
    checkOption(retOptions, "bindir", "pg_bin_directory", "-B")
    if "jsontop" not in retOptions:
        retOptions["jsontop"] = getPgaasPropValue("dcae_admin_db_jsontop")
    trace("env=%s" % str(os.environ))
    trace("ignorefile=%s" % ignoreFile)
    return retOptions, args

def main():
    keyedOptions, args = reviewOpts()
    trace("Invoked as: %s" % str(sys.argv))
    audit("Invoked as: %s" % str(sys.argv))

    if len(args) == 0:
        usage("no operation specified")
    elif args[0] == "configurationChanged":
        if len(args) != 2:
            usage("too many arguments")
        configurationChanged(keyedOptions, args[1])
    elif args[0] == "suspend":
        if len(args) != 1:
            usage("too many arguments")
        suspendOperations(keyedOptions)
    elif args[0] == "resume":
        if len(args) != 1:
            usage("too many arguments")
        resumeOperations(keyedOptions)
    elif args[0] == "test":
        if len(args) != 1:
            usage("too many arguments")
        testOperations(keyedOptions)
    elif args[0] == "newdb":
        if len(args) != 5:
            usage("wrong number of arguments")
        newDb(keyedOptions, args[1], args[2], args[3], args[4])
    else:
        usage("unrecognized operation '%s'" % args[0])

def suspendOperations(options):
    """
    Execute the "suspend" sub-command.
    """
    runProgram(["pkill", "repmgrd"])
    program = options["bindir"] + "/pg_ctl"
    cmd = [program, "stop", "-D", options["dbdir"]]
    runProgram(cmd)
    audit("suspendOperations")

def resumeOperations(options):
    """
    Execute the "resume" sub-command.
    """
    cmd = [options["bindir"] + "/pg_ctl", "start", "-D", options["dbdir"], "-o", "configfile=" + options["dbconf"]]
    runProgram(cmd)
    runProgram(["/opt/app/pgaas/bin/repmgrcd", "-d"])
    audit("resumeOperations")

def testOperations(options):
    """
    Respond to the "test" sub-command.
    """
    program = options["bindir"] + "/pg_ctl"
    cmd = [program, "status", "-D", options["dbdir"]]
    ret = runProgram(cmd)
    # pg_ctl: no server running
    # pg_ctl: server is running (PID: 13988)
    # does /var/run/postgresql/inmaintenance exist? -> YELLOW
    cmdRepmgr = ["pgrep", "repmgrd"]
    retRepmgr = runProgram(cmdRepmgr)
    
    msg = "????"
    if os.path.isfile("/var/run/postgresql/inmaintenance"):
        msg = "YELLOW: in maintenance mode"
    elif re.search("no server running", ret):
        msg = "RED: no PG server running"
    elif re.search("server is running", ret) and re.search("[0-9]+", retRepmgr):
        msg = "GREEN"
    elif re.search("server is running", ret):
        msg = "YELLOW: no repmgrd running"
    elif re.search("[0-9]+", retRepmgr):
        msg = "YELLOW: no PG server running"
    else:
        msg = "YELLOW: neither PG server nor repmgrd are running"
    audit("test: " + msg)
    print(msg, end="")

def runProgram(cmd):
    """
    Run the given command, returning the standard output as a string.
    If there is an error, return None.
    """
    try:
        p=subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
    except Exception as e:
        print("Error running program because: {0}".format(e), file=errorOutput)
        return None
    else:
        if stderr:
            print("Error running program because: {0} ".format(stderr), file=errorOutput)
            return None
        else:
            trace("runProgram() => " + str(stdout), minLevel=2)
            return stdout.decode('utf-8').rstrip('\n')

def configurationChanged(options, jsonFile):
    """
    We received a new JSON configuration file
    """
    audit("configurationChanged " + jsonFile)
    if options["ignorefile"] == "yes":
        trace("skipping database reconfiguration because skip_configuration_file exists")
        return

    if not os.path.isfile(jsonFile):
        die("json file %s does not exist" % jsonFile)

    try:
        inp = json.load(open(jsonFile,"r"))
    except Exception as e:
        die("Cannot open jsonFile '%s': %s" % (jsonFile, e))

    if verbose:
        dumpJSON(inp, "incoming JSON")

    jsonTop = options["jsontop"]
    if not jsonTop is None:
        e = "inp" + jsonTop
        trace("eval(%s)" % e)
        inp = eval(e,{"__builtins__":None},{"inp":inp})
        if verbose:
            dumpJSON(inp, "modified JSON")

    setupDictionaryDatabases(options, inp)

def setupDictionaryDatabases(options, inp):
    """
    Set up the databases listed in the dictionary
    """

    # trace("version=%s" % requireJSON("version", inp, "version"))
    requireJSON("databases", inp, "databases")
    con = None
    try:
        con = dbConnect(database = options["dbname"], user = options["dbuser"], password = options["dbpassword"], host = options["dbhost"])
        setupDatabases(con, options, requireJSON("databases", inp, "databases"))

    except psycopg2.DatabaseError as e:
        die('Error %s' % e)

    finally:
        if con:
            con.commit()
            con.close()

def newDb(options, dbName, adminPswd, userPswd, viewerPswd):
    """
    Given the database name and passwords, set up a database and corresponding users.
    For example, with dbname="foo", adminPswd="fooa", userPswd="foou" and viewerPswd="foov",
    act the same as if we had received the json configuration:
        {
            'databases': {
                'foo': {
                    'ownerRole': 'foo_admin',
                    'roles': {
                        'foo_admin': {
                            'password': 'fooa',
                            'role': 'admin'
                        },
                        'foo_user': {
                            'password': 'foou',
                            'role': 'writer'
                        },
                        'foo_viewer': {
                            'password': 'foov',
                            'role': 'reader'
                        }
                    }
                }
            }
        }
    """
    if not re.match("^[A-Za-z][A-Za-z0-9_]*$", dbName):
        errorPrint("'%s' is not a valid database name" % dbName)
        return

    adminName = dbName + "_admin"
    userName = dbName + "_user"
    viewerName = dbName + "_viewer"

    setupDictionaryDatabases(options, {
            'databases': {
                dbName: {
                    'ownerRole': adminName,
                    'roles': {
                        adminName: {
                            'password': adminPswd,
                            'role': 'admin'
                        },
                        userName: {
                            'password': userPswd,
                            'role': 'writer'
                        },
                        viewerName: {
                            'password': viewerPswd,
                            'role': 'reader'
                        }
                    }
                }
            }
        })

def dumpJSON(js, msg):
        tracePrint("vvvvvvvvvvvvvvvv %s" % msg)
        tracePrint(json.dumps(js, indent=4))
        tracePrint("^^^^^^^^^^^^^^^^ %s" % msg)

def setupDatabases(con, options, dbList):
    """
    Do what is needed to set up all of the databases
    """
    currentDatabases = dbGetFirstColumnAsMap(con, "select datname from pg_database where datistemplate = false")
    currentRolenames = dbGetFirstColumnAsMap(con, "select rolname from pg_roles")
    trace("currentDatabases = " + str(currentDatabases))
    for dbName in dbList:
        trace("dbName='%s'" % str(dbName))
        setupDatabase(con, options, currentDatabases, currentRolenames, dbName, dbList[dbName])

def setupDatabase(con, options, currentDatabases, currentRolenames, dbName, dbInfo):
    """
    Do what is needed to set up a given databases and its users
    """
    
    dbOwnerRole = requireJSON("databases[].ownerRole", dbInfo, "ownerRole")
    trace("dbName='%s', dbOwnerRole='%s'" % (dbName, dbOwnerRole))
    doesDbExist = dbName in currentDatabases
    trace("does %s exist? %s" % (dbName, doesDbExist))
    foundOwnerRole = False
    dbRoles = dbInfo["roles"]
    for name in dbRoles:
        u = dbRoles[name]
        if name == dbOwnerRole and u["role"] == "admin":
            foundOwnerRole = True
        if u["role"] not in ("admin","writer","reader"):
            die("For database %s, the role '%s' is not one of admin/writer/reader" % (dbName, u.role))
    if not foundOwnerRole:
        die("For database %s, information on the ownerRole '%s' was not found" % (dbName, dbOwnerRole))
    for name in dbRoles:
        userInfo = dbRoles[name]
        if name in currentRolenames and ("ignoredb" not in options or not options["ignoredb"]):
            trace("The role %s already exists, skipping" % name)
            updatePassword(con, options, dbName, name, userInfo)
        else:
            setupUser(con, options, dbName, name, userInfo)
    if doesDbExist and ("ignoredb" not in options or not options["ignoredb"]):
        trace("The database %s already exists, skipping" % dbName)
    else:
        makeDatabase(con, options, dbName, dbOwnerRole, dbInfo, dbRoles)
    for name in dbRoles:
        userInfo = dbRoles[name]
        if name in currentRolenames and ("ignoredb" not in options or not options["ignoredb"]):
            trace("The role %s already exists, skipping grants" % name)
        else:
            modifyGrants(con, options, dbName, name, userInfo)

def makeDatabase(con, options, dbName, dbOwnerRole, dbInfo, dbRoles):
    """
    Execute the SQL to create a database

    TODO: verify grants against what is actually there
    """
    ownerRole = dbInfo["ownerRole"]
    userRole = "{0}_common_user_role".format(dbName)
    viewerRole = "{0}_common_viewer_role".format(dbName)
        
    optionalDbExecute(con, options, "CREATE ROLE {0}".format(userRole))
    optionalDbExecute(con, options, "CREATE ROLE {0}".format(viewerRole))

    trace("Creating database %s with owner '%s'" % (dbName, ownerRole))
    optionalDbExecute(con, options, "CREATE DATABASE %s WITH OWNER %s" % (dbName, ownerRole))
    con2 = None
    try:
        con2 = dbConnect(database = dbName, user = options["dbuser"], password = options["dbpassword"], host = options["dbhost"])

        optionalDbExecute(con2, options, "REVOKE ALL on DATABASE {0} FROM {1}".format(dbName, viewerRole))
        optionalDbExecute(con2, options, "REVOKE ALL on DATABASE {0} FROM {1}".format(dbName, userRole))
        for name in dbRoles:
            userInfo = dbRoles[name]
            if userInfo["role"] == "writer" or userInfo["role"] == "reader":
                optionalDbExecute(con2, options, "REVOKE ALL on DATABASE {0} FROM {1}".format(dbName, name))

        #  user can do everything viewer can
        optionalDbExecute(con2, options, "GRANT {0} TO {1}".format(viewerRole, userRole))
        #  admin can do everything user and viewer can
        optionalDbExecute(con2, options, "GRANT {0} TO {1}".format(userRole, ownerRole))

        # viewer, user, admin can connect
        optionalDbExecute(con2, options, "GRANT CONNECT ON DATABASE {0} TO {1}".format(dbName, viewerRole))

        # create a schema we can optionally use *
        schemaName = "{0}_db_common".format(dbName)
        optionalDbExecute(con2, options, "CREATE SCHEMA if not exists {0} AUTHORIZATION {1}".format(schemaName, ownerRole))

        # search_path is not inherited, so set it here
        for role in [ ownerRole, userRole, viewerRole ]:
            optionalDbExecute(con2, options, "ALTER ROLE {1} IN DATABASE {0} SET search_path = public, {2}".format(dbName, role, schemaName))

        # viewer,user can select from schema
        optionalDbExecute(con2, options, "GRANT USAGE  ON SCHEMA {0} TO {1}".format(schemaName, viewerRole))
        # admin can create on schema
        optionalDbExecute(con2, options, "GRANT CREATE ON SCHEMA {0} TO {1}".format(schemaName, ownerRole))

        # viewer, user, admin can select on tables
        optionalDbExecute(con2, options, "ALTER DEFAULT PRIVILEGES FOR ROLE {1} GRANT SELECT ON TABLES TO {0}".format(viewerRole, ownerRole))
        # user, admin can ins/upd/del/tru on tables
        optionalDbExecute(con2, options, "ALTER DEFAULT PRIVILEGES FOR ROLE {1} GRANT INSERT, UPDATE, DELETE, TRUNCATE ON TABLES TO {0}".format(userRole, ownerRole))
        # user, admin can update on sequences
        optionalDbExecute(con2, options, "ALTER DEFAULT PRIVILEGES FOR ROLE {1} GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {0}".format(userRole, ownerRole))

        # user, admin can create temp tables
        optionalDbExecute(con2, options, "GRANT TEMP ON DATABASE {0} TO {1}".format(dbName, userRole))

        for name in dbRoles:
            userInfo = dbRoles[name]
            if userInfo["role"] == "writer":
                optionalDbExecute(con2, options, "GRANT {0} TO {1}".format(userRole, name))
            elif userInfo["role"] == "reader":
                optionalDbExecute(con2, options, "GRANT {0} TO {1}".format(viewerRole, name))

            # search_path is not inherited, so set it here
            optionalDbExecute(con2, options, "ALTER ROLE {1} IN DATABASE {0} SET search_path = public, {2}".format(dbName, name, schemaName))

    except psycopg2.DatabaseError as e:
        die('Error %s' % e)

    finally:
        if con2:
            con2.commit()
            con2.close()

def checkUsername(userName):
    """
    A value of type name is a string of 63 or fewer characters1. A name must start
    with a letter or an underscore; the rest of the string can contain letters,
    digits, and underscores.
    """
    trace("checkUsername(%s)" % userName)
    if re.match("[A-Za-z_][A-Za-z0-9_]*$", userName):
        return True
    else:
        errorPrint("%s is not a valid userName" % userName)
        return False

def setupUser(con, options, dbName, userName, userInfo):
    """
    Do what is needed to to set up a user for a database
    """
    if checkUsername(userName):
        trace("For dbName='%s', create user '%s'" % (dbName, userName))
        userPassword = userInfo["password"]
        optionalDbExecute(con, options, "create user %s with password '%s'" % (userName, userPassword))

def updatePassword(con, options, dbName, userName, userInfo):
    """
    Do what is needed to update a user's password 
    """
    if checkUsername(userName):
        trace("For dbName='%s', alter user '%s' password" % (dbName, userName))
        userPassword = userInfo["password"]
        optionalDbExecute(con, options, "alter user %s with password '%s'" % (userName, userPassword))

def modifyGrants(con, options, dbName, userName, userInfo):
    """
    Do what is needed to to set up a user for a database with the proper grants

    TODO: if user exist, verify current grants
    """
    if checkUsername(userName):
        userRole = userInfo["role"]
        trace("For dbName='%s', set up user '%s' as a '%s'" % (dbName, userName, userRole))
        if userRole == "writer":
            optionalDbExecute(con, options, "grant %s_common_user_role to %s" % (dbName, userName))
        elif userRole == "reader":
            optionalDbExecute(con, options, "grant %s_common_viewer_role to %s" % (dbName, userName))
        # elif userRole == "admin":
        #     optionalDbExecute(con, options, "grant %s_common_admin_role to %s" % (dbName, userName))
        else:
            trace("nothing to grant %s" % userName)

def optionalDbExecute(con, options, cmd):
    if "nocreate" in options and options["nocreate"]:
        print(cmd)
    else:
        audit("Running: " + cmd)
        dbExecute(con, cmd)

"""
database utility functions
"""

# def dbGetMap(con, cmd, args=[], skipTrace=False):
# def dbGetOneRowMap(con, cmd, args=[], skipTrace=False):

def dbGetFirstRowOneValue(con, cmd, args=[], skipTrace=False):
    """
    Do a select and return a single value from the first row
    """
    row = dbGetFirstRow(con, cmd, args, skipTrace)
    trace("row=" + str(row))
    if row is not None and len(row) > 0:
        return row[0]
    return None

def dbGetFirstRow(con, cmd, args=[], skipTrace=False):
    """
    Do a select and return the values from the first row
    """
    cursor = dbExecute(con, cmd, args, skipTrace)
    return cursor.fetchone()

def dbGetFirstColumn(con, cmd, args=[], skipTrace=False):
    """
    Do a select and return the first column's value from each row
    """
    ret = []
    cursor = dbExecute(con, cmd, args, skipTrace)
    for row in cursor:
        for col in row:
            ret.append(col)
            break
    return ret

def dbGetFirstColumnAsMap(con, cmd, args=[], skipTrace=False, val=1):
    """
    Do a select and return the first column's value from each row
    """
    ret = {}
    cursor = dbExecute(con, cmd, args, skipTrace)
    for row in cursor:
        for col in row:
            ret[col] = val
            break
    return ret

def dumpTable(con, tableName, max=-1):
    """
    If being extra verbose, print out the entire table
    """
    if verbose < 2:
        return
    print("================ " + tableName + " ================", file=traceOutput)

    cols = dbGetFirstColumn(con, "select column_name from information_schema.columns where table_name='" + tableName + "'", skipTrace=True)
    print("num", end="|", file=traceOutput)
    for col in cols:
        print(col, end="|", file=traceOutput)
    print("", file=traceOutput)

    if max > -1:
        cursor = dbExecute(con, "select * from " + tableName + " limit " + str(max), skipTrace=True)
    else:
        cursor = dbExecute(con, "select * from " + tableName, skipTrace=True)
    i = 0
    for row in cursor:
        print("%d" % i, end="|", file=traceOutput)
        i += 1
        for col in row:
            print("%s" % (col), end="|", file=traceOutput)
        print("", file=traceOutput)
    print("================================================", file=traceOutput)

def dbExecute(con, statement, args=[], skipTrace=False):
    """
    Create a cursor, instantiate the arguments into a statement, trace print the statement, and execute the statement.
    Return the cursor
    """
    cursor = con.cursor()
    stmt = cursor.mogrify(statement, args);
    if not skipTrace:
        trace("executing:" + str(stmt))
    cursor.execute(stmt)
    global quiet
    if not skipTrace:
        trace("statusmessage=" + cursor.statusmessage + ", rowcount=" + str(cursor.rowcount))
    return cursor

def dbConnect(database, user, password, host, autocommit = True):
    """
    Create a connection, logging it in the process
    Return the connection
    """
    trace("connecting to database %s as %s on host %s" % (database, user, host))
    con =psycopg2.connect(database = database, user = user, password = password, host = host)
    con.autocommit = autocommit
    return con

"""
Utility functions
"""

def die(msg):
    """
    Print a message to the error file and exit.
    """
    errorPrint(msg)
    sys.exit(1)

def errorPrint(msg, file=errorOutput):
    """
    Print a message to the error file.
    """
    global errorLogger
    # print("----------------> errorLogger=%s" % str(errorLogger))
    if errorLogger is not None:
        errorLogger.error(msg)
    else:
        taggedPrint("ERROR", msg, file=file)
        

def tracePrint(msg, file=traceOutput):
    """
    Print a message to the trace file.
    """
    global debugLogger
    # print("----------------> debugLogger=%s" % str(debugLogger))
    if debugLogger is not None:
        debugLogger.debug(msg)
    else:
        taggedPrint("DEBUG", msg, file=file)

def taggedPrint(tag, msg, file):
    """
    Print a message to the trace file.
    """
    dt = time.strftime('%Y-%m-%d %T', time.localtime())
    print("%s %s: %s" % (dt, tag, msg), file=file)

def requireOption(nm, val):
    """
    Die if a program parameter is not set
    """
    return require("option", nm, val)

def requireJSON(prnm, dict, nm):
    """
    Die if a JSON value is not set
    """
    if nm not in dict:
        die("The JSON value '%s' is missing" % prnm)
    return dict[nm]

def require(type, nm, val):
    """
    Die if a value is not set
    """
    if val is None:
        die("The %s '%s' is missing" % (type, nm))
    return val

def trace(msg, minLevel=1):
    """
    Print a message to trace output if verbose is turned on.
    """
    global verbose
    if verbose >= minLevel:
        tracePrint(msg)

def audit(msg):
    """
    Print a message to audit log if one is being used
    """
    global auditLogger
    if auditLogger is not None:
        auditLogger.info(msg)

def getCdfPropValue(nm, encrypted=False, cfg="/opt/app/cdf/lib/cdf.cfg", dflt=None, skipComplaining=False):
    """
    Return a value from the configuration file /opt/app/cdf/lib/cdf.cfg
    """
    return getPropValue(nm=nm, encrypted=encrypted, cfg=cfg, dflt=dflt, skipComplaining=skipComplaining)

def getPgaasPropValue(nm, encrypted=False, cfg="/opt/app/pgaas/lib/pgaas.cfg", dflt=None, skipComplaining=False):
    """
    Return a value from the configuration file /opt/app/pgaas/lib/pgaas.cfg
    """
    return getPropValue(nm=nm, encrypted=encrypted, cfg=cfg, dflt=dflt, skipComplaining=skipComplaining)

getPropDict = { }

def getPropValue(nm, encrypted=False, cfg=None, dflt=None, skipComplaining=False):
    """
    Return a value from the specified configuration file 
    """
    if cfg is None:
        return None
    global getPropDict
    if getPropDict.get(cfg):
        savedDate = getPropDict[cfg]
        # trace("getPropValue: savedDate[" + cfg + "]=" + str(savedDate))
        cfgDate = os.path.getmtime(cfg)
        # trace("getPropValue: cfgDate=" + str(cfgDate))
        if float(savedDate) >= float(cfgDate): # cfg has not changed
            val = getPropDict.get(cfg + ":" + nm)
            # trace("getPropValue: val=" + val)
            if val is not None:
                # trace("getPropValue: getPropValue(saved) => '%s'" % str(val))
                return val
        else: # clear out any previously saved keys
            cfgcolon = cfg + ":"
            for k in list(getPropDict.keys()):
                if re.match(cfgcolon, k):
                    del getPropDict[k]
    getPropValueProgram = '/opt/app/cdf/bin/getpropvalue'
    if encrypted:
        cmd = [getPropValueProgram, "-f", cfg, "-x", "-n", nm]
    else:
        cmd = [getPropValueProgram, "-f", cfg, "-n", nm]
    # trace("getPgaasPropValue: cmd=" + str(cmd))

    try:
        with subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
            (origString, stderrString) = p.communicate()
    except Exception as e:
        traceback.print_exc()
        print("Error decoding string because {0}".format(e), file=errorOutput)
        return None
    else:
        if stderrString:
            if not re.search("Configuration property .* must be defined", stderrString.decode('utf-8')) and not skipComplaining:
                print("Error decoding string because: {0} ".format(stderr), file=errorOutput)
            return dflt
        else:
            trace("getPgaasPropValue() => " + str(origString), minLevel=2)
            return origString.decode('utf-8').rstrip('\n')

if __name__ == "__main__":
    main()
