#!/usr/bin/env python3
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


import http.server
import time, os, sys, re, subprocess, traceback, html, base64
import psycopg2
# TODO - move lots of code to a common library to share with other python modules
# sys.path.append("/opt/app/postgres-prep/lib")
# import dbtools

getLogDict = { }
def openLogFile(fname):
    """
    Open a log file for append and remember the file descriptor.
    Remember its inode/dev pair.
    If either changes, reopen it.
    """
    reopen = False
    try:
        curstat = os.stat(fname)
    except:
        reopen = True
    global getLogDict
    # print("top: reopen(%s)=%s" % (fname, reopen))
    if not reopen and getLogDict.get(fname):
        # print("found getLogDict.get(" + fname + ")")
        d = getLogDict[fname]
        fd = d["fd"] if "fd" in d else None
        oldstat = d["stat"] if "stat" in d else None
        if fd is None:
            reopen = True
        elif oldstat is None:
            reopen = True
        elif oldstat.st_ino != curstat.st_ino or oldstat.st_dev != curstat.st_dev:
            reopen = True
    if reopen or not getLogDict.get(fname):
        # print("closing old fd")
        oldd = getLogDict.get(fname)
        if oldd is not None:
            oldfd = oldd.get("fd")
            if oldfd is not None:
                oldfd.close()
        # print("reopening " + fname)
        fd = open(fname, "a")
        st = os.stat(fname)
        getLogDict[fname] = { "fd": fd, "stat": st }
    return getLogDict[fname]["fd"]

debugOn = False
testOn = False

if len(sys.argv) > 1:
    debugOn = True
    testOn = True

else:
    sys.stderr = openLogFile("/opt/app/log/postgresql/idns/error.log")

HOST_NAME = os.popen("hostname -f").readlines()[0].strip()
PORT_NUMBER = 8000

validPerDbTables = [ "pg_tables", "pg_indexes", "pg_views" ]
topButton = "&nbsp;<font size='1'><a href='#'>^</a></font>"

def traceMsg(msg):
    """ print a trace message. By default, this goes to trace.out """
    file = sys.stderr if testOn else openLogFile("/opt/app/log/postgresql/idns/trace.log")
    print(time.asctime(), msg, file=file)
    file.flush()

def errTrace(msg):
    """ print an error message. By default, sys.stderr is rerouted to error.log """
    file = sys.stderr if testOn else openLogFile("/opt/app/log/postgresql/idns/error.log")
    sys.stderr = file
    print(time.asctime(), msg, file=file)
    file.flush()

def debugTrace(msg):
    """ print a debug message. By default, this goes to debug.log """
    if debugOn:
        file = sys.stderr if testOn else openLogFile("/opt/app/log/postgresql/idns/debug.log")
        print(time.asctime(), msg, file=file)
        file.flush()

def readFile(file, defStr = None, mode = "r"):
    """ read a file and return its contents """
    ret = defStr
    try:
        with open(file, mode) as f:
            ret = f.read()
    except Exception as e:
        if defStr is not None:
            ret = defStr
            pass
        else:
            raise e
    return ret

def readFileBinary(file, defStr = None):
    return readFile(file, defStr = defStr, mode = "rb")

def readFileHtml(file, defStr = None):
    """ read a file and return its contents, escaping anything important to HTML """
    return html.escape(readFile(file, defStr))

def readPipe(cmd, ignoreError = False):
    """ read a pipe and return its contents """
    ret = ""
    try:
        with os.popen(cmd) as p:
            ret = p.read()
    except Exception as e:
        if ignoreError:
            pass
        else:
            raise e
    return ret

def readPipeHtml(file, defStr = None):
    """ read a pipe and return its contents, escaping anything important to HTML """
    return html.escape(readPipe(file, defStr))

def readFileOrGz(file, defStr = None):
    """ read a file and return its contents. If the file ends in .gz, use gunzip on it """
    if file.endswith(".gz"):
        return readPipe("gunzip < '" + file + "'", defStr)
    else:
        return readFile(file, defStr)

def readFileOrGzHtml(file, defStr = None):
    """ read a file and return its contents, escaping anything important to HTML. If the file ends in .gz, use gunzip on it """
    return html.escape(readFileOrGz(file, defStr))

def getCdfPropValue(nm, encrypted=False, cfg="/opt/app/cdf/lib/cdf.cfg", dflt=None):
    """
    Return a value from the configuration file /opt/app/cdf/lib/cdf.cfg
    """
    return getPropValue(nm=nm, encrypted=encrypted, cfg=cfg, dflt=dflt)

def getPgaasPropValue(nm, encrypted=False, cfg="/opt/app/pgaas/lib/pgaas.cfg", dflt=None):
    """
    Return a value from the configuration file /opt/app/pgaas/lib/pgaas.cfg
    """
    return getPropValue(nm=nm, encrypted=encrypted, cfg=cfg, dflt=dflt)

getPropDict = { }

def getPropValue(nm, encrypted=False, cfg=None, dflt=None):
    """
    Return a value from the specified configuration file 
    """
    if cfg is None:
        return None
    global getPropDict
    if getPropDict.get(cfg):
        savedDate = getPropDict[cfg]
        debugTrace("getPropValue: savedDate[" + cfg + "]=" + str(savedDate))
        cfgDate = os.path.getmtime(cfg)
        debugTrace("getPropValue: cfgDate=" + str(cfgDate))
        if float(savedDate) >= float(cfgDate): # cfg has not changed
            val = getPropDict.get(cfg + ":" + nm)
            debugTrace("getPropValue: val=" + str(val))
            if val is not None:
                debugTrace("getPropValue: getPropValue(saved) => '%s'" % str(val))
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
    debugTrace("getPropValue: cmd=%s" % str(cmd))

    try:
        with subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE) as p:
            (origString, stderrString) = p.communicate()
    except Exception as e:
        traceback.print_exc()
        errTrace("Error decoding string because {0}".format(e))
        return None
    else:
        if stderrString:
            if not re.search("Configuration property .* must be defined", stderrString.decode('utf-8')): # and dflt is not None:
                errTrace("Error decoding string because: {0} ".format(stderrString))
            return dflt
        else:
            debugTrace("getPropValue() => '%s'" % str(origString))
            getPropDict[cfg] = os.path.getmtime(cfg)
            val = origString.decode('utf-8').rstrip('\n')
            debugTrace("getPropValue() => '%s'" % val)
            getPropDict[cfg + ":" + nm] = val
            return val

def checkFileAge(full_path,number_of_days):
    """
    return True if the file is >= number_of_days old from right now
    """
    time_n_days_ago = time.time() - (number_of_days * 24 * 60 * 60)
    stat = os.stat(full_path)
    return time_n_days_ago >= stat.st_mtime

def jumpTable(prefix, *args):
    """
    Return a string consisting of a series of <a href='#prefix-xxx'>xxx</a>.
    Include <font size='1'></font> around all of it.
    """
    header = "<font size='1'>"
    sep = ""
    for table in args:
        header = header + sep + "<a href='#" + prefix + "-" + table + "'>" + table + "</a> "
        sep = " | "
    header = header + "</font>"
    return header

def addFilenameHrefs(prefix, str):
    """
    for each line in a list of filenames, change the last two elements of the path to an anchor.
    """
    ret = ""
    for line in str.splitlines():
        line = re.sub("/([^/]+)/([^/]+)$", '/\g<1>' + "/<a href='" + prefix + '\g<1>/\g<2>' + "'>" + '\g<2>' + "</a>", line)
        ret = ret + line + "\n"
    return ret

def ifEmpty(str, defStr):
    """ if a string is empty, return the defStr in its place """
    if str is None or str == "":
        str = defStr
    return str

def isExe(fname):
    """ check if a path exists and is executable """
    return os.path.exists(fname) and os.access(fname, os.X_OK)

class MyHandler(http.server.BaseHTTPRequestHandler):

    def isServerUp(self):
        """
        Check if the postgres server is up and running by calling pg_ctl and
        looking for "server is running" (or "no server running").
        Then call ps -fu postgres and make sure we're not waiting on a master:
        postgres  20815  20812  0 15:52 ?        00:00:00 postgres: startup process   waiting for 000000010000000000000001
        """
        PGCTLPATH1 = "/usr/lib/postgresql/9.6/bin/pg_ctl"
        PGCTLPATH2 = "/usr/lib/postgresql/9.5/bin/pg_ctl"
        PGCTLPATH3 = "/opt/app/postgresql-9.5.2/bin/pg_ctl"
        if isExe(PGCTLPATH1):
            statusLines = readPipe(PGCTLPATH1 + " status -D /dbroot/pgdata/main/")
        elif isExe(PGCTLPATH2):
            statusLines = readPipe(PGCTLPATH2 + " status -D /dbroot/pgdata/main/")
        else:
            statusLines = readPipe(PGCTLPATH3 + " status -D /dbroot/pgdata/main/")
        debugTrace("isServerUp(): statusLines = %s" % statusLines)
        psLines = readPipe("ps -fu postgres")
        debugTrace("isServerUp(): ps -fu postgres = %s" % psLines)
        ret = len(statusLines) > 0 and re.search("server is running", statusLines, re.MULTILINE) and not re.search("startup process\\s+waiting", psLines, re.MULTILINE)
        debugTrace("isServerUp(): returning = %s" % ret)
        return ret

    def isRepmgrdUp(self):
        """
        Check if the repmgrd server is up and running by calling "pgrep repmgrd" and
        looking for a process id.
        """
        statusLines = readPipe("pgrep repmgrd")
        debugTrace("isServerUp(): statusLines = %s" % statusLines)
        ret = len(statusLines) > 0 and re.search("[0-9]+", statusLines, re.MULTILINE) != None
        debugTrace("isServerUp(): returning = %s" % ret)
        return ret

    def isMaster(self):
        """
        Check if the postgresql server is a master by asking the server if it is in recovery (meaning not a master)
        """
        ret = None
        con = None
        try:
            pwd = getCdfPropValue("postgres", True)
            # debugTrace("using pwd=%s" % pwd)
            con = psycopg2.connect(database = "postgres", user="postgres", password=pwd, host= HOST_NAME)
            str = dbGetFirstRowOneValue(con, "select pg_is_in_recovery()")
            debugTrace("pg_is_in_recovery() <= %s" % str)
            ret = not str

        except psycopg2.DatabaseError as e:
            errTrace('Database Error %s' % e)

        except Exception as e:
            traceback.print_exc()
            errTrace(str(e))

        finally:
            if con is not None:
                con.close()

        debugTrace("isMaster(): returning = %s" % ret)
        return ret

    def hasRepmgr(self):
        """
        Check if the postgresql server is a master by asking the server if it is in recovery (meaning not a master)
        """
        ret = None
        con = None
        try:
            pwd = getCdfPropValue("postgres", True)
            # debugTrace("using pwd=%s" % pwd)
            con = psycopg2.connect(database = "postgres", user="postgres", password=pwd, host= HOST_NAME)
            str = dbGetFirstRowOneValue(con, "select * from pg_database where datname = 'repmgr'")
            debugTrace("repmgr database check() <= %s" % str)
            ret = str

        except psycopg2.DatabaseError as e:
            errTrace('Database Error %s' % e)

        except Exception as e:
            traceback.print_exc()
            errTrace(str(e))

        finally:
            if con is not None:
                con.close()

        debugTrace("isMaster(): returning = %s" % ret)
        return ret

    def isValidPgHost(self, host):
        """
        Check a hostname against the list of nodes stored in the pgnodes CDF configuration file.
        """
        pgnodes = getCdfPropValue("pgnodes", "").split('|')
        ret = host in pgnodes
        debugTrace("isValidPgHost(): looking for host='%s' in pgnodes='%s' => %s" % (host, str(pgnodes), ret))
        return ret

    def checkAuth(self):
        """
        HTTP/1.1 401 Unauthorized
        Date: Mon, 04 Feb 2014 16:50:53 GMT
        WWW-Authenticate: Basic realm="WallyWorld"

        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        """
        pswd = getCdfPropValue("wgetpswd", True)
        b64pswd = base64.b64encode(("pgaas:" + pswd).encode("ascii"))
        basicPlusPswd = "Basic %s" % b64pswd.decode("ascii")

        if self.headers['Authorization'] == None:
            return False
        elif self.headers['Authorization'] == basicPlusPswd:
            return True
        else:
            return False

    def pgStatus(self, *pgargs):
        """ return a table(s), using the system database of postgres """
        return self.pgStatusDBx("postgres", *pgargs)

    def pgStatusDB(self, DB, *pgargs):
        """ return a table(s), using the given database """
        return self.pgStatusDBx(DB, *pgargs)

    def pgStatusDBx(self, DB, *pgargs):
        """ return a table(s), using the given database """
        debugTrace("pgStatusDBx(DB=" + DB + ")")
        con = None
        ret = None
        try:
            con = psycopg2.connect(database = DB, user="postgres", password=getCdfPropValue("postgres", True), host= HOST_NAME)
            ret = getTableHtmls(con, DB, pgargs)

        except psycopg2.DatabaseError as e:
            errTrace('Database Error %s' % e)

        except Exception as e:
            traceback.print_exc()
            errTrace(str(e))

        finally:
            if con is not None:
                con.close()

        return ret

    def do_HEAD(self):
        """Respond to a HEAD request."""
        self.doHEADandGET(False)

    def do_GET(self):
        """Respond to a GET request."""
        self.doHEADandGET(True)

    def doHEADandGET(self, sendMsg):
        resp = 400
        msg = ""
        sendBinary = False
        contentType = "text/plain"
        global debugOn

        if self.path == "/statusall":
            self.path = "/all/status/pgstatus"
        elif self.path == "/pgstatusall":
            self.path = "/pgstatus"

        if self.path == '/ro':
            if os.path.isfile("/var/run/postgresql/force-ro-off"):
                isrw = "FORCE-RO-OFF"
            elif os.path.isfile("/var/run/postgresql/force-ro-on"):
                isrw = "Secondary"
            else:
                isrw = readFile("/var/run/postgresql/isrw", "n/a")
            debugTrace("/ro: isrw returns %s" % isrw)
            if re.match("Secondary", isrw) or re.match("Master", isrw):
                resp = 200
                msg = "server is up"
            else:
                msg = "server is not up " + isrw
                errTrace("/ro: isrw returns %s" % isrw)
            
        elif self.path == '/rw':
            isrw = readFile("/var/run/postgresql/isrw", "n/a")
            debugTrace("/rw: isrw returns %s" % isrw)
            if re.match("Master", isrw):
                resp = 200
                msg = "master server is up"
            elif re.match("Secondary", isrw):
                msg = "non-master server is up"
            else:
                msg = "server is not up " + isrw
                errTrace("/ro: isrw returns %s" % isrw)

        elif self.path == '/isrw':
            isrw = readFile("/var/run/postgresql/isrw", "n/a")
            debugTrace("/isrw: returns %s" % isrw)
            resp = 200
            msg = isrw

        elif self.path == '/healthcheck/status':
            hs = readFile("/var/run/postgresql/check_cluster", "n/a")
            debugTrace("/healthcheck/status: returns %s" % hs)
            resp = 429 if hs == "n/a" else 200
            msg = '{ "output": "' + re.sub('"', "'", re.sub("\n", " ", hs)) + '" }'

        elif not self.checkAuth():
            resp = 401
            msg = "not authenticated"

        elif self.path == '/ismaster':
            masterYes = self.isMaster()
            msg = ""
            if masterYes:
                resp = 200
                msg = "master server"
            else:
                msg = "non-master server"

        elif self.path == '/issecondary':
            masterYes = self.isMaster()
            msg = ""
            if not masterYes:
                resp = 200
                msg = "secondary server"
            else:
                msg = "non-secondary server"

        elif self.path == '/ismaintenance':
            msg = ""
            if os.path.exists("/var/run/postgresql/inmaintenance"):
                resp = 200
                msg = "in maintenance mode"
            else:
                msg = "not in maintenance mode"

        elif self.path == '/getpubkey':
            try:
                resp = 200
                msg = readFile(os.path.expanduser("~postgres/.ssh/id_rsa.pub"))
            except:
                traceback.print_exc()
                resp = 404
                msg = "key does not exist"

        elif re.match("/getssh/", self.path):
            # getssh/hostname - push ssh pub/private keys across
            host = re.sub("^/getssh/", "", self.path)
            debugTrace("#1: /getssh/ host='%s'" % host)
            host = re.sub("[^a-zA-Z0-9_.-]", "", host)
            debugTrace("#2: /getssh/ host='%s'" % host)
            if self.isValidPgHost(host):
                p = readPipe("scp -o StrictHostKeyChecking=no -i ~postgres/.ssh/id_rsa ~postgres/.ssh/id_rsa* postgres@" + host + ":.ssh/ 2>&1")
                debugTrace("#3: /getssh/ to '%s' returns '%s'" % (host, p))
                msg = "OK " + p
                resp = 200
            else:
                msg = "NOT OK INVALID HOST"
                resp = 404

        elif re.match("/getcdf/", self.path):
            # getcdf/hostname - push cdf.cfg file across
            fi = "/opt/app/cdf/lib/cdf.cfg"
            # make sure that the file exists and contains the encrypted postgres password
            if re.search("postgres.x", readFile(fi, "n/a")) and re.search("repmgr.x", readFile(fi, "n/a")):
                host = re.sub("^/getcdf/", "", self.path)
                debugTrace("#1: /getcdf/ host='%s'" % host)
                host = re.sub("[^a-zA-Z0-9_.-]", "", host)
                debugTrace("#2: /getcdf/ host='%s'" % host)
                if self.isValidPgHost(host):
                    p = readPipe("scp -o StrictHostKeyChecking=no -i ~postgres/.ssh/id_rsa " + fi + " postgres@" + host + ":/opt/app/cdf/lib/cdf.cfg 2>&1")
                    debugTrace("#3: /getcdf/ to '%s' returns '%s'" % (host, p))
                    msg = "OK " + p
                    resp = 200
                else:
                    msg = "NOT OK INVALID HOST"
                    resp = 404
            else:
                msg = "NOT OK YET"
                resp = 404

        elif self.path == '/hasrepmgr':
            repmgrYes = self.hasRepmgr()
            msg = ""
            if repmgrYes:
                resp = 200
                msg = "OK"
            else:
                msg = "NOT OK YET"

        elif self.path == '/status':
            resp = 200
            contentType = "text/html"
            isServerUp = self.isServerUp()
            isRepmgrdUp = self.isRepmgrdUp()
            isMaster = self.isMaster()
            color = "green" if (isServerUp and isRepmgrdUp) else "yellow" if (isServerUp or isRepmgrdUp) else "red"
            dashed = "solid" if isMaster else "dashed"
            jump = jumpTable("status", "ps", "repmgr", "df", "uptime", "loadavg", "cpuinfo", "meminfo", "pgaas-failures", "pgaas-inst-report", "nslookup", "ip-addr-show", "who-br")

            msg = """<table style='border: 10px %s %s' width='100%%'><tr><td>
                <b>isServerUp</b> %s
                <b>isRepmgrdUp</b> %s
                <b>isMaster</b> %s
                <b>isrw</b> %s %s\n<br/>
                %s
                <h2><a name='status-ps'>ps</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-repmgr'>repmgr cluster show</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-df'>df</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-uptime'>uptime</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2>/proc/uptime%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-loadavg'>loadavg</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-cpuinfo'>cpuinfo</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-meminfo'>meminfo</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-pgaas-failures'>pgaas-failures</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-pgaas-inst-report'>pgaas.inst.report</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-nslookup'>nslookup</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-ip-addr-show'>ip addr</a>%s</h2>\n<pre>\n%s\n</pre>\n
                <h2><a name='status-who-br'>who -br</a>%s</h2>\n<pre>\n%s\n</pre>\n
                </td></tr></table>""" % (color, dashed, isServerUp, isRepmgrdUp, isMaster,
                readFileHtml("/var/run/postgresql/isrw", "n/a"),
                readPipeHtml("hostname -f"), jump,
                topButton, readPipeHtml("ps -fu postgres"),
                topButton, readPipeHtml("/opt/app/pgaas/bin/repmgrc cluster show"),
                topButton, readPipeHtml("df -h"),
                topButton, readPipeHtml("uptime", defStr="n/a"),
                topButton, readFileHtml("/proc/uptime", defStr="n/a"),
                topButton, readFileHtml("/proc/loadavg", defStr="n/a"),
                topButton, readFileHtml("/proc/cpuinfo", defStr="n/a"),
                topButton, readFileHtml("/proc/meminfo", defStr="n/a"),
                topButton, readFileHtml("/tmp/pgaas-failures", defStr="n/a"),
                topButton, readFileHtml("/tmp/pgaas.inst.report", defStr="n/a"),
                topButton, readPipeHtml("nslookup $(hostname -f)", defStr="n/a"),
                topButton, readPipeHtml("ip addr show", defStr="n/a"),
                topButton, readPipeHtml("who -br", defStr="n/a"))

        elif self.path == '/stoplight':
            isServerUp = self.isServerUp()
            isRepmgrdUp = self.isRepmgrdUp()
            isMaster = self.isMaster()
            color = "green" if (isServerUp and isRepmgrdUp) else "yellow" if (isServerUp or isRepmgrdUp) else "red"
            masterSecondary = "master" if isMaster else "secondary"
            sendBinary = True
            contentType = "image/gif"
            msg = readFileBinary("/opt/app/postgresql-prep/lib/stoplight-" + masterSecondary + "-" + color + ".gif", "")

        elif re.match("/perdb-", self.path):
            # /perdb-
            rest = re.sub("^/perdb-", "", self.path)
            debugTrace("#1: /perdb- others='%s'" % rest)
            rest = re.sub("[^a-zA-Z0-9_./-]", "", rest)
            debugTrace("#2: /perdb- rest='%s'" % rest)
            pgothers = [ x for x in rest.split('-') if x in validPerDbTables ]
            resp = 200
            contentType = "text/html"
            con = None
            try:
                pwd = getCdfPropValue("postgres", True)
                con = psycopg2.connect(database = "postgres", user="postgres", password=pwd, host= HOST_NAME)
                databases = dbGetFirstColumn(con, "select datname from pg_database")
                debugTrace("after select datname from pg_database")
                databases[:] = [DB for DB in databases if not re.match("template[0-9]", DB)]
                msg = msg + jumpTable("db", *databases) + "<br/>"
                for DB in databases:
                    debugTrace("looking at DB=" + DB)
                    msg = msg + "<h1><a name='db-" + DB + "'>" + DB + "</a>" + topButton + "</h1>\n"
                    msg = msg + jumpTable(DB + "-table", *pgothers)
                    msg = msg + self.pgStatusDB(DB, *pgothers)

            except psycopg2.DatabaseError as e:
                errTrace('Database Error %s' % e)
                msg = "DB is down"

            except Exception as e:
                traceback.print_exc()
                errTrace(str(e))

            finally:
                if con is not None:
                    con.close()

        elif self.path == '/pgstatus':
            tables = [ "pg_stat_activity", "pg_stat_archiver", "pg_stat_bgwriter", "pg_stat_database", "pg_stat_database_conflicts", "pg_stat_user_tables", "pg_stat_user_indexes", "pg_statio_user_tables", "pg_statio_user_indexes", "pg_statio_user_sequences", "pg_roles", "pg_database", "pg_tables", "pg_namespace", "pg_roles", "pg_group" ]
            header = jumpTable("postgres-table", *tables)
            msg = self.pgStatus(*tables)
            if msg is not None:
                contentType = "text/html"
                resp = 200
                msg = header + msg

        elif self.path == '/pg_stat_activity':
            msg = self.pgStatus("pg_stat_activity")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_stat_archiver':
            msg = self.pgStatus("pg_stat_archiver")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_stat_bgwriter':
            msg = self.pgStatus("pg_stat_bgwriter")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_stat_database':
            msg = self.pgStatus("pg_stat_database")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_stat_database_conflicts':
            msg = self.pgStatus("pg_stat_database_conflicts")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_stat_user_tables':
            msg = self.pgStatus("pg_stat_user_tables")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_stat_user_indexes':
            msg = self.pgStatus("pg_stat_user_indexes")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_statio_user_tables':
            msg = self.pgStatus("pg_statio_user_tables")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_statio_user_indexes':
            msg = self.pgStatus("pg_statio_user_indexes")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_statio_user_sequences':
            msg = self.pgStatus("pg_statio_user_sequences")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_roles':
            msg = self.pgStatus("pg_roles")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_database':
            msg = self.pgStatus("pg_database")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_tables':
            msg = self.pgStatus("pg_tables")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_namespace':
            msg = self.pgStatus("pg_namespace")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif self.path == '/pg_group':
            msg = self.pgStatus("pg_group")
            if msg is not None:
                contentType = "text/html"
                resp = 200

        elif re.match("/all/", self.path) or re.match("/small/", self.path):
            if re.match("/small/", self.path):
                height = 40
            else:
                height = 400
            # /all/others
            rest = re.sub("^/all/", "", self.path)
            rest = re.sub("^/small/", "", self.path)
            rest = re.sub("[^a-zA-Z0-9_./-]", "", rest)
            debugTrace("/all/ rest='%s'" % rest)
            others = rest.split('/')
            try:
                resp = 200
                contentType = "text/html"
                pgnodes = getCdfPropValue("pgnodes", "").split('|')
                msg = msg + jumpTable("node", *pgnodes)
                for node in pgnodes:
                    hnode = html.escape(node)
                    msg = msg + "<h2><a name='node-" + hnode + "'>" + hnode + "</a>" + topButton + "</h2>\n"
                    msg = msg + jumpTable(hnode + "-other", *others)
                    for other in others:
                        msg = msg + "<h3><a name='" + hnode + "-other-" + other + "'>" + other + "</a>" + topButton + "</h3>\n"
                        msg = msg + "<iframe src='http://" + hnode + ":" + str(PORT_NUMBER) + "/" + other + "'      frameborder='1' scrolling='yes' height='" + str(height) + "' width='1200'></iframe>\n"
            except Exception as e:
                traceback.print_exc()
                errTrace(str(e))


        elif self.path == '/debugon':
            msg = "ON"
            resp = 200
            debugOn = True

        elif self.path == '/debugoff':
            msg = "OFF"
            resp = 200
            debugOn = False

        elif self.path == '/log' or  self.path == '/log/':
            msg = "<h2>%s</h2><pre>\n%s\n</pre>" % (self.path, addFilenameHrefs("/log/", readPipeHtml("ls -l /opt/app/log/postgresql/*/*")))
            resp = 200
            contentType = "text/html"

        elif self.path == '/mlog' or  self.path == '/mlog/':
            # /opt/app/dcae-controller-service-common-vm-manager/logs
            msg = "<h2>%s</h2><pre>\n%s\n</pre>" % (self.path, addFilenameHrefs("/mlog/", readPipeHtml("ls -l /opt/app/dcae-controller-service-common-vm-manager/logs/*")))
            resp = 200
            contentType = "text/html"

        elif self.path == '/tmp' or self.path == '/tmp/':
            msg = "<h2>%s</h2><pre>\n%s\n</pre>" % (self.path, addFilenameHrefs("/tmp/", readPipeHtml("ls -l /tmp/*")))
            resp = 200
            contentType = "text/html"

        elif re.match("/log/", self.path):
            # /log/dir/path
            rest = re.sub("^/log/", "", self.path)
            debugTrace("#1: /log/ others='%s'" % rest)
            rest = re.sub("[^a-zA-Z0-9_./-]", "", rest)
            rest = re.sub("/[.][.]/", "", rest)
            debugTrace("#2: /log/ rest='%s'" % rest)
            msg = "<h2>%s</h2><pre>\n%s\n</pre>" % (rest, ifEmpty(readFileOrGzHtml("/opt/app/log/postgresql/" + rest, "n/a"), "<i>empty</i>"))
            resp = 200
            contentType = "text/html"

        elif re.match("/mlog/", self.path):
            # /log/dir/path
            rest = re.sub("^/mlog/", "", self.path)
            debugTrace("#1: /mlog/ others='%s'" % rest)
            rest = re.sub("[^a-zA-Z0-9_./-]", "", rest)
            rest = re.sub("/[.][.]/", "", rest)
            rest = re.sub("^logs/", "", rest)
            debugTrace("#2: /mlog/ rest='%s'" % rest)
            msg = "<h2>%s</h2><pre>\n%s\n</pre>" % (rest, ifEmpty(readFileOrGzHtml("/opt/app/dcae-controller-service-common-vm-manager/logs/" + rest, "n/a"), "<i>empty</i>"))
            resp = 200
            contentType = "text/html"

        elif re.match("/tmp/", self.path):
            # /log/dir/path
            rest = re.sub("^/tmp/", "", self.path)
            debugTrace("#1: /tmp/ others='%s'" % rest)
            rest = re.sub("[^a-zA-Z0-9_./-]", "", rest)
            rest = re.sub("/[.][.]/", "", rest)
            rest = re.sub("^tmp/", "", rest)
            debugTrace("#2: /tmp/ rest='%s'" % rest)
            msg = "<h2>%s</h2><pre>\n%s\n</pre>" % (rest, ifEmpty(readFileOrGzHtml("/tmp/" + rest, "n/a"), "<i>empty</i>"))
            resp = 200
            contentType = "text/html"

        elif self.path == '/oldro':
            serverYes = self.isServerUp()
            if serverYes:
                resp = 200
                msg = "server is up"
            else:
                msg = "server is not up"

        elif self.path == '/oldrw':
            serverYes = self.isServerUp()
            masterYes = self.isMaster()
            msg = ""
            if serverYes:
                if masterYes:
                    resp = 200
                    msg = "master server is up"
                elif masterYes is not None:
                    msg = "non-master server is up"
                else:
                    msg = "master status is up, but not answering"
            else:
                if masterYes:
                    msg = "status is down, but responded as master server"
                elif masterYes is not None:
                    msg = "status is down, but responded as non-master"
                else:
                    msg = "status is down, server is not up"

        elif self.path == "/help":
            resp = 200
            contentType = "text/html"
            msg = """<pre>
                <a href='/statusall'>statusall</a> == all/status/pgstatus
                <a href='/ro'>ro</a> == iDNS readonly
                <a href='/rw'>rw</a> == iDNS readwrite
                <a href='/isrw'>isrw</a> == /var/run/postgresql/isrw
                <a href='/ismaster'>ismaster</a> == is master
                <a href='/issecondary'>issecondary</a> == is secondary
                <a href='/ismaintenance'>ismaintenance</a> == is in maintenance mode
                <a href='/getpubkey'>getpubkey</a> == retrieve public key
                <a href='/hasrepmgr'>hasrepmgr</a> == repmgr id and database are set up
                <a href='/status'>status</a> == lots of info
                <a href='/perdb-pg_tables-pg_indexes-pg_views'>perdb</a>-{<a href='/perdb-pg_tables'>pg_tables</a>-<a href='/perdb-pg_indexes'>pg_indexes</a>-<a href='/perdb-pg_views'>pg_views</a>} == info per DB
                <a href='/pgstatus'>pgstatus</a> == lots of database info
                <a href='/pg_stat_activity'>pg_stat_activity</a>, <a href='/pg_stat_archiver'>pg_stat_archiver</a>, <a href='/pg_stat_bgwriter'>pg_stat_bgwriter</a>,
                <a href='/pg_stat_database'>pg_stat_database</a>, <a href='/pg_stat_database_conflicts'>pg_stat_database_conflicts</a>, <a href='/pg_stat_user_tables'>pg_stat_user_tables</a>,
                <a href='/pg_stat_user_indexes'>pg_stat_user_indexes</a>, <a href='/pg_statio_user_tables'>pg_statio_user_tables</a>, <a href='/pg_statio_user_indexes'>pg_statio_user_indexes</a>,
                <a href='/pg_statio_user_sequences'>pg_statio_user_sequences</a>,
                <a href='/pg_roles'>pg_roles</a>, <a href='/pg_database'>pg_database</a>,
                <a href='/pg_tables'>pg_tables</a>, <a href='/pg_namespace'>pg_namespace</a>,
                <a href='/pg_group'>pg_group</a>,
                <a href='/swmstatus'>swm proc_out files</a>
                <a href='/log'>log</a> == ls -l logs
                log/foo == log foo
                <a href='/mlog'>mlog</a> == ls -l manager logs
                mlog/foo == mlog foo
                <a href='/tmp'>tmp</a> == ls -l /tmp
                </pre>"""
        else:
            resp = 404
            msg = "path does not exist"

        # TODO == encode msg when binary
        if sendBinary:
            debugTrace("%s: Returning %d/%d/%s" % (self.path, resp, len(msg), "--binary--"))
        else:
            debugTrace("%s: Returning %d/%d/%s" % (self.path, resp, len(msg), msg))
        traceMsg("- %s - \"%s %s %s\" %d %d" % (self.client_address[0], self.command, self.path, self.request_version, resp, len(msg)))
        self.send_response(resp)
        if resp == 401:
            self.send_header('WWW-Authenticate', 'Basic realm="PGaaS"')
        self.send_header("Content-type", contentType)
        self.end_headers()
        if sendMsg:
            if msg is None:
                msg = ""
            if sendBinary:
                self.wfile.write(msg)
            else:
                self.wfile.write((msg + "\n").encode("utf-8"))
        sys.stderr.flush()

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
    debugTrace("row=" + str(row))
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
    traceOutput = sys.stderr if testOn else openLogFile("/opt/app/log/postgresql/idns/debug.log")
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

def getTableHtmls(con, DB, tableNames):
    """
    Retrieve a dump of all specified tables, in HTML format
    """
    ret = ""
    for tn in tableNames:
        ret = ret + getTableHtml(con, DB, tn)
    return ret

def getTableHtml(con, DB, tableName, max=-1):
    """
    Retrieve a dump of a given table, in HTML format
    """
    # errTrace("getting %s" % str(tableName))
    ret = "<h2><a name='" + DB + "-table-" + tableName + "'>" + DB + "&nbsp;" + tableName + "</a>" + topButton + "</h2>\n"
    ret = ret + "<table border='1'>\n"
    # ret = ret + "<tr><th colspan='" + str(len(cols)+1) + "'>" + tableName + "</th></tr>\n"
    cols = dbGetFirstColumn(con, "select column_name from information_schema.columns where table_name='" + tableName + "'", skipTrace=True)

    ret = ret + "<tr><th>num</th>"
    for col in cols:
        ret = ret + "<th>" + str(col) + "</th>"
    ret = ret + "</tr>\n"

    if max > -1:
        cursor = dbExecute(con, "select * from " + tableName + " limit " + str(max), skipTrace=True)
    else:
        cursor = dbExecute(con, "select * from " + tableName, skipTrace=True)
    i = 0
    for row in cursor:
        ret = ret + "<tr><th>" + str(i) + "</th>"
        i = i + 1
        for col in row:
            ret = ret + "<td>" + str(col) + "</td>"
        ret = ret + "</tr>\n"
    ret = ret + "</table>\n"
    return ret

def dbExecute(con, statement, args=[], skipTrace=False):
    """
    Create a cursor, instantiate the arguments into a statement, trace print the statement, and execute the statement.
    Return the cursor
    """
    cursor = con.cursor()
    stmt = cursor.mogrify(statement, args);
    if not skipTrace:
        debugTrace("executing:" + str(stmt))
    cursor.execute(stmt)
    if not skipTrace:
        debugTrace("statusmessage=" + cursor.statusmessage + ", rowcount=" + str(cursor.rowcount))
    return cursor

if __name__ == '__main__':
    server_class = http.server.HTTPServer
    httpd = server_class(("0.0.0.0", PORT_NUMBER), MyHandler)
    errTrace("Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    errTrace("Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER))
