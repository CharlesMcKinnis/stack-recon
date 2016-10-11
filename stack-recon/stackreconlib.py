#!/usr/bin/env python
import re
import glob
import subprocess
import sys
import os
import mysql.connector
import string
from mysql.connector import errorcode
from xml.parsers.expat import ExpatError
# import platform
# import yaml
import fnmatch
try:
    import xml.etree.ElementTree as ET
except ImportError:
    import cElementTree as ET
import pprint
import socket
# required for Magento 2
try:
    import json
    JSON = True
except ImportError:
    # Primarily RHEL 5 issue, and breaks Magento 2 queries
    JSON = False
# try:
#     import argparse
#     ARGPARSE = True
# except ImportError:
#     ARGPARSE = False
#     sys.stderr.write("This program is more robust if python argparse "
#                      "installed.\n")
#     # error_collection.append("This program is more robust if python "
#                               "argparse installed.\n")
# try:
#     import mysql.connector
#     MYSQL = True
# except ImportError:
#     MYSQL = False
#     sys.stderr.write("This program will be more robust if mysql.connector "
#                      "installed.\n")
#     error_collection.append("This program will be more robust if "
#                             "mysql.connector installed.\n")

"""
Magento is a trademark of Varien. Neither I nor these scripts are affiliated
with or endorsed by the Magento Project or its trademark owners.
"""
"""
git clone https://github.com/CharlesMcKinnis/stack-recon.git
#dev branch
cd stack-recon && git checkout -b dev origin/dev
./ecomm-recon 2>&1 |tee report-`date +%b%d-%H%M`.txt|less

To look at the json captured:
cat config_dump.json |python -m json.tool|less
"""
STACK_LIB_VERSION = 2016092801
error_collection = []


class argsAlt(object):
    pass


class apacheCtl(object):
    def __init__(self, daemon, **kwargs):
        self.daemon = daemon
        self.kwargs = kwargs
        if "exe" not in self.kwargs:
            self.daemon["exe"] = "httpd"
            # self.kwargs["exe"] = "httpd"
    """
    [root@527387-db1 26594]# httpd -V
    # returns key: value
    Server version: Apache/2.2.15 (Unix)
    Server built:   Aug 25 2015 04:30:38
    Server's Module Magic Number: 20051115:25
    Server loaded:  APR 1.3.9, APR-Util 1.3.9
    Compiled using: APR 1.3.9, APR-Util 1.3.9
    Architecture:   64-bit
    Server MPM:     Prefork
      threaded:     no
        forked:     yes (variable process count)
    Server compiled with....
    # returns key=value
     -D APACHE_MPM_DIR="server/mpm/prefork"
     -D APR_HAS_SENDFILE
     -D APR_HAS_MMAP
     -D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
     -D APR_USE_SYSVSEM_SERIALIZE
     -D APR_USE_PTHREAD_SERIALIZE
     -D APR_HAS_OTHER_CHILD
     -D AP_HAVE_RELIABLE_PIPED_LOGS
     -D DYNAMIC_MODULE_LIMIT=128
     -D HTTPD_ROOT="/etc/httpd"
     -D SUEXEC_BIN="/usr/sbin/suexec"
     -D DEFAULT_PIDLOG="run/httpd.pid"
     -D DEFAULT_SCOREBOARD="logs/apache_runtime_status"
     -D DEFAULT_LOCKFILE="logs/accept.lock"
     -D DEFAULT_ERRORLOG="logs/error_log"
     -D AP_TYPES_CONFIG_FILE="conf/mime.types"
     -D SERVER_CONFIG_FILE="conf/httpd.conf"
    """
    def figlet(self):
        print """
    _                     _
   / \   _ __   __ _  ___| |__   ___
  / _ \ | '_ \ / _` |/ __| '_ \ / _ \\
 / ___ \| |_) | (_| | (__| | | |  __/
/_/   \_\ .__/ \__,_|\___|_| |_|\___|
        |_|
"""

    def get_version(self):
        """
        Discovers installed apache version
        """
        if self.kwargs["exe"].endswith("apache2"):
            version = 'apache2ctl -v'
        else:
            version = self.kwargs["exe"] + " -v"
        p = subprocess.Popen(version,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        else:
            return(output)

    def get_conf_parameters(self):
        if self.kwargs["exe"].endswith("apache2"):
            conf = 'apache2ctl -V 2>&1'
        else:
            conf = self.kwargs["exe"] + " -V 2>&1"
        p = subprocess.Popen(conf,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        dict = {}
        compiled = 0
        for i in output.splitlines():
            if i.strip() == "Server compiled with....":
                compiled = 1
                continue
            if compiled == 0:
                result = re.match('\s*([^:]+):\s*(.+)', i.strip())
                if result:
                    dict[result.group(1)] = result.group(2)
            else:
                result = re.match('\s*-D\s*([^=]+)=?"?([^"\s]*)"?', i.strip())
                if result:
                    dict[result.group(1)] = result.group(2)
        return dict

    def get_root(self):
        try:
            return self.get_conf_parameters()['HTTPD_ROOT']
        except KeyError:
            sys.stderr.write("apache error: Failed to get root.\n")
            error_collection.append("apace error: Failed to get root.\n")
            sys.exit(1)

    def get_conf(self):
        """
        :returns: configuration path location
        HTTPD_ROOT/SERVER_CONFIG_FILE
        """
        try:
            return os.path.join(self.get_conf_parameters()['HTTPD_ROOT'], self.get_conf_parameters()['SERVER_CONFIG_FILE'])
        except KeyError:
            sys.stderr.write("apache error: Failed to get conf.\n")
            error_collection.append("apace error: Failed to get conf.\n")
            sys.exit(1)

    def get_mpm(self):
        try:
            return self.get_conf_parameters()['Server MPM']
        except KeyError:
            sys.stderr.write("apache error: Failed to get mpm.\n")
            error_collection.append("apace error: Failed to get mpm.\n")
            sys.exit(1)

    def parse_config(self, wholeconfig):
        """
        list structure
        { line: { listen: [ ], server_name: [ ], root: path } }
        <VirtualHost *:80>
        DocumentRoot /var/www/vhosts/example.com/httpdocs
        ServerName example.com
        ServerAlias www.example.com
        <Directory /var/www/vhosts/example.com/httpdocs>
        </Directory>
        CustomLog /var/log/httpd/example.com-access_log combined
        ErrorLog /var/log/httpd/example.com-error_log
        </VirtualHost>
        <VirtualHost _default_:443>
        ErrorLog logs/ssl_error_log
        TransferLog logs/ssl_access_log
        LogLevel warn
        SSLEngine on
        SSLProtocol all -SSLv2 -SSLv3 -TLSv1
        SSLCipherSuite DEFAULT:!EXP:!SSLv2:!DES:!IDEA:!SEED:+3DES
        SSLCertificateFile /etc/pki/tls/certs/localhost.crt
        SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
        </VirtualHost>
        """
        stanza_chain = []
        stanza_count = 0
        vhost_start = -1
        # location_start = 0
        linenum = 0
        filechain = []
        stanza_flags = []
        stanzas = {}  # AutoVivification()
        base_keywords = ["serverroot", "startservers", "minspareservers",
                         "maxspareservers", "maxclients", "maxrequestsperchild",
                         "listen"]
        vhost_keywords = ["documentroot", "servername", "serveralias",
                          "customlog", "errorlog", "transferlog", "loglevel",
                          "sslengine", "sslprotocol", "sslciphersuite",
                          "sslcertificatefile", "sslcertificatekeyfile",
                          "sslcacertificatefile", "sslcertificatechainfile"]
        prefork_keywords = ["startservers", "minspareservers", "maxspareservers",
                            "maxclients", "maxrequestsperchild", "listen",
                            "serverlimit"]
        worker_keywords = ["startservers", "maxclients", "minsparethreads",
                           "maxsparethreads", "threadsperchild",
                           "maxrequestsperchild"]
        event_keywords = ["startservers", "minspareservers", "maxspareservers",
                          "serverlimit", "threadsperchild", "maxrequestworkers",
                          "maxconnectionsperchild", "minsparethreads",
                          "maxsparethreads"]
        lines = iter(wholeconfig.splitlines())
        for line in lines:
            linenum += 1
            linecomp = line.strip().lower()
            # if the line opens < but doesn't close it with > there is probably
            # a \ and newline and it should be concat with the next line until
            # it closes with > if a line ends in \, it is continued on the next
            # line
            while linecomp.endswith("\\"):
                linecomp = linecomp.strip("\\").strip()
                # read the next line
                line = lines.next()
                linenum += 1
                linecomp += " "
                linecomp += line.strip().lower()
            # when we start or end a file, we inserted ## START or END so we
            # could identify the file in the whole config as they are opened, we
            # add them to a list, and remove them as they close. Then we can use
            # their name to identify where it is configured
            filechange = re.match("## START (.*)", line)
            if filechange:
                filechain.append(filechange.group(1))
                if vhost_start == -1:
                    if "config_file" not in stanzas:
                        stanzas["config_file"] = []
                    stanzas["config_file"].append(filechange.group(1))
                continue
            filechange = re.match("## END (.*)", line)
            if filechange:
                filechain.pop()
                continue
            # listen, documentroot
            # opening VirtualHost
            result = re.match('<[^/]\s*(\S+)', linecomp)
            if result:
                stanza_count += 1
                stanza_chain.append({"linenum": linenum, "title": result.group(1)})
            result = re.match('</', linecomp)
            if result:
                stanza_count -= 1
                stanza_chain.pop()
            # base configuration
            if stanza_count == 0:
                keywords = base_keywords + vhost_keywords
                if "config" not in stanzas:
                    stanzas["config"] = {}
                update(stanzas["config"], kwsearch(keywords, linecomp))
            # prefork matching
            result = re.match('<ifmodule\s+prefork.c', linecomp, re.IGNORECASE)
            if result:
                stanza_flags.append({"type": "prefork", "linenum": linenum,
                                     "stanza_count": stanza_count})
                continue
            # prefork ending
            result = re.match('</ifmodule>', linecomp, re.IGNORECASE)
            if result:
                # you may encounter ending modules, but not have anything in
                #   flags, and if so, there is nothing in it to test
                if len(stanza_flags) > 0:
                    if stanza_flags[-1]["type"] == "prefork" and stanza_flags[-1]["stanza_count"] == stanza_count + 1:
                        stanza_flags.pop()
                        continue
            # If we are in a prefork stanza
            if len(stanza_flags) > 0:
                if stanza_flags[-1]["type"] == "prefork" and stanza_flags[-1]["stanza_count"] == stanza_count:
                    if "prefork" not in stanzas:
                        stanzas["prefork"] = {}
                    update(stanzas["prefork"], kwsearch(prefork_keywords, line,
                                                        single_value=True))
                    continue
            # worker matching
            result = re.match('<ifmodule\s+worker.c', linecomp, re.IGNORECASE)
            if result:
                stanza_flags.append({"type": "worker", "linenum": linenum, "stanza_count": stanza_count})
            result = re.match('</ifmodule>', linecomp, re.IGNORECASE)
            if result:
                # you may encounter ending modules, but not have anything in
                #   flags, and if so, there is nothing in it to test
                if len(stanza_flags) > 0:
                    if (stanza_flags[-1]["type"] == "worker" and
                            stanza_flags[-1]["stanza_count"] == stanza_count + 1):
                        stanza_flags.pop()
            # If we are in a prefork stanza
            if len(stanza_flags) > 0:
                if (stanza_flags[-1]["type"] == "worker" and
                        stanza_flags[-1]["stanza_count"] == stanza_count):
                    if "worker" not in stanzas:
                        stanzas["worker"] = {}
                    update(stanzas["worker"], kwsearch(worker_keywords,
                                                       linecomp,
                                                       single_value=True))
                    continue
            # event matching
            result = re.match('<ifmodule\s+mpm_event', linecomp, re.IGNORECASE)
            if result:
                stanza_flags.append({"type": "event", "linenum": linenum,
                                     "stanza_count": stanza_count})
            result = re.match('</ifmodule>', linecomp, re.IGNORECASE)
            if result:
                # you may encounter ending modules, but not have anything in
                #   flags, and if so, there is nothing in it to test
                if len(stanza_flags) > 0:
                    if (stanza_flags[-1]["type"] == "event" and
                            stanza_flags[-1]["stanza_count"] == stanza_count + 1):
                        stanza_flags.pop()
            # If we are in a prefork stanza
            if len(stanza_flags) > 0:
                if (stanza_flags[-1]["type"] == "event" and
                        stanza_flags[-1]["stanza_count"] == stanza_count):
                    if "event" not in stanzas:
                        stanzas["event"] = {}
                    update(stanzas["event"],
                           kwsearch(event_keywords,
                                    linecomp,
                                    single_value=True))
                    continue
            """
<IfModule mpm_event_module>
    StartServers             3
    MinSpareThreads         75
    MaxSpareThreads        250
    ServerLimit             32
    ThreadsPerChild         25
   MaxRequestWorkers      800
    MaxConnectionsPerChild   0
</IfModule>
"""
            # virtual host matching
            result = re.match('<virtualhost\s+([^>]+)', linecomp, re.IGNORECASE)
            if result:
                server_line = str(linenum)
                vhost_start = stanza_count
                if server_line not in stanzas:
                    stanzas[server_line] = {}
                stanzas[server_line]["virtualhost"] = result.group(1)
                if "config_file" not in stanzas[server_line]:
                    stanzas[server_line]["config_file"] = []
                # there should only be one config file, but just in case, we
                #   will append it
                if filechain[-1] not in stanzas[server_line]["config_file"]:
                    stanzas[server_line]["config_file"].append(filechain[-1])
                # if this is a server { start, there shouldn't be anything else
                #   on the line
                continue
            # only match these in a virtual host
            if vhost_start == stanza_count:
                keywords = vhost_keywords
                update(stanzas[server_line], kwsearch(keywords, line.strip()))
            # closing VirtualHost
            result = re.match('</virtualhost', linecomp, re.IGNORECASE)
            if result:
                vhost_start = -1
                continue
            # end virtual host matching
        # this section is so the same information shows up in nginx and apache,
        #   to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] = []
        for i in stanzas.keys():
            if (("documentroot" in stanzas[i]) or
                    ("servername" in stanzas[i]) or
                    ("serveralias" in stanzas[i]) or
                    ("virtualhost" in stanzas[i])):
                configuration["sites"].append({})
                if "servername" in stanzas[i]:
                    if "domains" not in configuration["sites"][-1]:
                        configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["servername"]
                if "serveralias" in stanzas[i]:
                    if "domains" not in configuration["sites"][-1]:
                        configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["serveralias"]
                if "virtualhost" in stanzas[i]:
                    if "listening" not in configuration["sites"][-1]:
                        configuration["sites"][-1]["listening"] = []
                    configuration["sites"][-1]["listening"] += [stanzas[i]["virtualhost"]]
                if "documentroot" in stanzas[i]:
                    configuration["sites"][-1]["doc_root"] = stanzas[i]["documentroot"][0]
                if "config_file" in stanzas[i]:
                    configuration["sites"][-1]["config_file"] = stanzas[i]["config_file"][0]
                if "customlog" in stanzas[i]:
                    configuration["sites"][-1]["access_log"] = stanzas[i]["customlog"][0]
                if "errorlog" in stanzas[i]:
                    configuration["sites"][-1]["error_log"] = stanzas[i]["errorlog"][0]
        update(stanzas, configuration)
        # there was a stanzas["config"] but that isn't what is referenced later
        if "maxprocesses" not in stanzas:
            mpm = self.get_mpm().lower()
            if mpm == "prefork":
                if stanzas.get("prefork", {}).get("maxclients"):
                        stanzas["maxprocesses"] = int(stanzas["prefork"]["maxclients"])
            elif mpm == "event":
                if "event" in stanzas:
                    """
                    Two directives set hard limits on the number of active
                    child processes and the number of server threads in a
                    child process, and can only be changed by fully stopping
                    the server and then starting it again. ServerLimit is a
                    hard limit on the number of active child processes, and
                    must be greater than or equal to the MaxRequestWorkers
                    directive divided by the ThreadsPerChild directive.
                    ThreadLimit is a hard limit of the number of server
                    threads, and must be greater than or equal to the
                    ThreadsPerChild directive.
                    """
                    if stanzas.get("event", {}).get("serverlimit"):
                        event_limit_one = int(stanzas["event"]["serverlimit"])
                    else:
                        event_limit_one = None
                    if (stanzas.get("event", {}).get("maxrequestworkers") and
                            stanzas.get("event", {}).get("threadsperchild")):
                        event_limit_two = int(stanzas["event"]["maxrequestworkers"]) / int(stanzas["event"]["threadsperchild"])
                    else:
                        event_limit_two = None
                    if event_limit_one is not None and event_limit_two is not None:
                        if event_limit_one < event_limit_two:
                            stanzas["maxprocesses"] = event_limit_one
                        else:
                            stanzas["maxprocesses"] = event_limit_two
                    elif event_limit_one is not None:
                        stanzas["maxprocesses"] = event_limit_one
                    elif event_limit_two is not None:
                        stanzas["maxprocesses"] = event_limit_two
            elif mpm == "worker":
                if "worker" in stanzas:
                    if stanzas.get("worker", {}).get("maxclients"):
                        stanzas["maxprocesses"] = int(stanzas["worker"]["maxclients"])
            else:
                sys.stderr.write("Could not identify mpm in use.\n")
                error_collection.append("apache error: Could not identify mpm "
                                        "in use.\n")
                sys.exit(1)
            pass
        return stanzas


class nginxCtl(object):
    def __init__(self, daemon, **kwargs):
        self.daemon = daemon
        self.kwargs = kwargs
        if "exe" not in self.kwargs:
            self.daemon["exe"] = "nginx"
            # self.kwargs["exe"] = "nginx"
    """
    A class for nginxCtl functionalities
    """
    """
    # nginx -V
    nginx version: nginx/1.0.15
    built by gcc 4.4.7 20120313 (Red Hat 4.4.7-11) (GCC)
    TLS SNI support enabled
    configure arguments: --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/var/run/nginx.pid --lock-path=/var/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module --with-http_image_filter_module --with-http_geoip_module --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_stub_status_module --with-http_perl_module --with-mail --with-mail_ssl_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' --with-ld-opt=-Wl,-E
    """
    def figlet(self):
        print """
             _
 _ __   __ _(_)_ __ __  __
| '_ \ / _` | | '_ \\\ \/ /
| | | | (_| | | | | |>  <
|_| |_|\__, |_|_| |_/_/\_\\
       |___/
"""

    def get_version(self):
        """
        Discovers installed nginx version
        """
        version = self.kwargs["exe"] + " -v 2>&1"
        p = subprocess.Popen(version,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        else:
            return(output)

    def get_conf_parameters(self):
        """
        Finds nginx configuration parameters
        :returns: list of nginx configuration parameters
        """
        conf = self.kwargs["exe"] + " -V 2>&1 | grep 'configure arguments:'"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        output = re.sub('configure arguments:', '', output)
        dict = {}
        for item in output.split(" "):
            if len(item.split("=")) == 2:
                dict[item.split("=")[0]] = item.split("=")[1]
        # nginx command line params
        # nginx: master process /usr/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
        # result = re.search('\((\S+)\)', phpfpm_process["cmd"])
        # if result:
        #     return(result.group(1))
        result = re.search('-c\s+(\S+)', self.daemon["cmd"])
        if result:
            dict['--conf-path'] = result.group(1)
        return dict

    def get_conf(self):
        """
        :returns: nginx configuration path location
        """
        try:
            return self.get_conf_parameters()['--conf-path']
        except KeyError:
            sys.stderr.write("nginx error: Failed to get configuration.\n")
            error_collection.append("nginx error: Failed to get "
                                    "configuration.\n")
            sys.exit(1)

    def get_bin(self):
        """
        :returns: nginx binary location
        """
        # try:
        if True:
            return self.get_conf_parameters()['--sbin-path']

    def get_pid(self):
        """
        :returns: nginx pid location which is required by nginx services
        """
        # try:
        if True:
            return self.get_conf_parameters()['--pid-path']

    def get_lock(self):
        """
        :returns: nginx lock file location which is required for nginx services
        """
        # try:
        if True:
            return self.get_conf_parameters()['--lock-path']

    def parse_config(self, wholeconfig):
        """
        list structure
        { line: { listen: [ ], server_name: [ ], root: path } }
        """
        stanza_chain = []
        configfile_vars = {}
        stanza_count = 0
        server_start = -1
        # server_line = -1
        # location_start = 0
        linenum = 0
        filechain = []
        stanzas = {}  # AutoVivification()
        # keywords
        server_keywords = ["listen", "root", "ssl_prefer_server_ciphers",
                           "ssl_protocols", "ssl_ciphers", "access_log",
                           "error_log"]
        server_keywords_split = ["server_name"]
        for line in wholeconfig.splitlines():
            linenum += 1
            # this is where I need to add variable parsing
            nginxset = re.match("\s*set\s+(\$[a-zA-Z0-9_]+)\s+[\"']?([^\"\s';]*)[\"']?;", line)
            if nginxset:
                configfile_vars[nginxset.group(1)] = nginxset.group(2)
                # print "set match: %s" % (line)
                # print "group1: %s" % (nginxset.group(1))
                # print "group1: %s" % (nginxset.group(2))
            # if line contains \s$(varname)\s replace varname with
            #   nginxvars[group(1)]
            # http://nginx.org/en/docs/http/ngx_http_rewrite_module.html#set
            # Syntax: 	set $variable value;
            # Default:
            # Context: 	server, location, if
            # "\s*(server|location|if)\s+[^$]*($[\S]+)" # find a the first
            #   variable occurrence
            # look in the line for a variable
            restring = "(\s*(server|location|if|root)\s+[^$]*)(\$[a-zA-Z0-9_]+)(.*)"
            nginx_var_match = re.match(restring, line)
            # while there is a match
            while nginx_var_match:
                # if there is a match, run a sub with the varname and the
                #   varvalue
                # print "before line %r" % line
                if (configfile_vars.get(nginx_var_match.group(3)) is not None and
                        nginx_var_match.group(3) is not None):
                    line = re.sub(r"%s" % restring, r"\g<1>%s\g<4>" %
                                  configfile_vars.get(nginx_var_match.group(3),
                                                      ""),
                                  line)
                    # look in the line for another variable
                    nginx_var_match = re.match(restring, line)
                else:
                    break
            linecomp = line.strip().lower()
            # when we start or end a file, we inserted ## START or END so we
            #   could identify the file in the whole config
            # as they are opened, we add them to a list, and remove them as
            #   they close.
            # then we can use their name to identify where it is configured
            filechange = re.match("## START (.*)", line)
            if filechange:
                filechain.append(filechange.group(1))
            filechange = re.match("## END (.*)", line)
            if filechange:
                filechain.pop()
            # filechain[-1] for the most recent element
            # this doesn't do well if you open and close a stanza on the same line
            if len(re.findall('{', line)) > 0 and len(re.findall('}', line)) > 0:
                if "error" not in stanzas:
                    stanzas["error"] = "nginx config file: This script does not consistently support opening { and closing } stanzas on the same line.\n"
                    error_collection.append("WARNING: nginx config file: This "
                                            "script does not consistently "
                                            "support opening { and closing } "
                                            "stanzas on the same line.\n")
                stanzas["error"] += "line %d: %s\n" % (linenum, line.strip())
                error_collection.append("line %d: %s\n" % (linenum, line.strip()))
            stanza_count += len(re.findall('{', line))
            stanza_count -= len(re.findall('}', line))
            result = re.match("(\S+)\s*{", linecomp)
            if result:
                stanza_chain.append({"linenum": linenum,
                                     "title": result.group(1)})
            if len(re.findall('}', line)) and len(stanza_chain) > 0:
                stanza_chain.pop()
            # start server { section
            # is this a "server {" line?
            result = re.match('^\s*server\s', linecomp, re.IGNORECASE)
            if result:
                server_start = stanza_count
                server_line = str(linenum)
                if server_line not in stanzas:
                    stanzas[server_line] = {}
                if "config_file" not in stanzas[server_line]:
                    stanzas[server_line]["config_file"] = []
                # there should only be one config file, but just in case, 
                # we will append it
                if not filechain[-1] in stanzas[server_line]["config_file"]:
                    stanzas[server_line]["config_file"].append(filechain[-1])
                # continue # if this is a server { start, there shouldn't be
                # anything else on the line
            # are we in a server block, and not a child stanza of the server
            # block? is so, look for keywords this is so we don't print the
            # root directive for location as an example. That might be useful,
            # but isn't implemented at this time.
            if server_start == stanza_count:
                # we are in a server block
                # result = re.match('\s*(listen|server|root)', line.strip())
                keywords = server_keywords
                if server_line not in stanzas:
                    stanzas[server_line] = {}
                update(stanzas[server_line], kwsearch(keywords, line))
                keywords = server_keywords_split
                if server_line not in stanzas:
                    stanzas[server_line] = {}
                if "server_name" not in stanzas[server_line]:
                    stanzas[server_line]["server_name"] = []
                if kwsearch(["server_name"], line):
                    stanzas[server_line]["server_name"] += kwsearch(["server_name"], line)["server_name"][0].split()
                """
                for word in keywords:
                    result = re.match("\s*(%s)\s*(.*)" % word, line.strip("\s\t;"), re.IGNORECASE)
                    if result:
                        if not word in stanzas[server_line]:
                            stanzas[server_line][word] = []
                        stanzas[server_line][word] += [result.group(2)]
                """
            elif stanza_count < server_start:
                # if the server block is bigger than the current stanza, we
                # have left the server stanza we were in
                # if server_start > stanza_count and server_start > 0:
                # The lowest stanza_count goes is 0, so it is redundant
                # we are no longer in the server { block
                server_start = -1
            # end server { section
            # keywords is a list of keywords to search for
            # look for keywords in the line
            # pass the keywords to the function and it will extract the keyword
            #   and value
            keywords = ["worker_processes"]
            update(stanzas, kwsearch(keywords, line))
        # print "configfile_vars: %r" % configfile_vars
        # this section is so the same information shows up in nginx and apache,
        # to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] = []
        # pressing the whole web daemon config in to a specific framework so it
        #   is easier to work with
        for i in stanzas.keys():
            # fixes an error where i = 'error' and the contents are a string
            if type(stanzas[i]) is not list and type(stanzas[i]) is not dict:
                continue
            if ("root" in stanzas[i]) or ("server_name" in stanzas[i]) or ("listen" in stanzas[i]):
                # "access_log", "error_log"
                configuration["sites"].append({})
                if "server_name" in stanzas[i]:
                    if "domains" not in configuration["sites"][-1]:
                        configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["server_name"]
                if "listen" in stanzas[i]:
                    if "listening" not in configuration["sites"][-1]:
                        configuration["sites"][-1]["listening"] = []
                    configuration["sites"][-1]["listening"] += stanzas[i]["listen"]
                if "root" in stanzas[i]:
                    configuration["sites"][-1]["doc_root"] = stanzas[i]["root"][0]
                if "config_file" in stanzas[i]:
                    configuration["sites"][-1]["config_file"] = stanzas[i]["config_file"][0]
                if "access_log" in stanzas[i]:
                    configuration["sites"][-1]["access_log"] = stanzas[i]["access_log"][0]
                if "error_log" in stanzas[i]:
                    configuration["sites"][-1]["error_log"] = stanzas[i]["error_log"][0]
        update(stanzas, configuration)
        if "worker_processes" in stanzas:
            try:
                stanzas["maxprocesses"] = int(stanzas["worker_processes"][0])
            except ValueError:
                stanzas["maxprocesses"] = -1
        return stanzas


class phpfpmCtl(object):
    def __init__(self, daemon, **kwargs):
        self.daemon = daemon
        """ example contents will be only the dict in { }
        'php-fpm': { 'cmd': 'php-fpm: master process (/etc/php-fpm.conf)',
                     'basename': 'php-fpm',
                     'exe': '/usr/sbin/php-fpm'
                   }
        """
        self.kwargs = kwargs
        if "exe" not in self.kwargs:
            self.kwargs["exe"] = "php-fpm"

    def figlet(self):
        print """
       _                  __
 _ __ | |__  _ __        / _|_ __  _ __ ___
| '_ \| '_ \| '_ \ _____| |_| '_ \| '_ ` _ \\
| |_) | | | | |_) |_____|  _| |_) | | | | | |
| .__/|_| |_| .__/      |_| | .__/|_| |_| |_|
|_|         |_|             |_|
"""

    def get_version(self):
        """
        Discovers installed nginx version
        """
        # version = self.kwargs["exe"]+" -v"
        version = self.daemon["exe"] + " -v"
        p = subprocess.Popen(version,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        else:
            return(output)

    def get_conf_parameters(self):
        conf = self.daemon["exe"] + " -V 2>&1"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        dict = {}
        compiled = 0
        for i in output.splitlines():
            if i.strip() == "Server compiled with....":
                compiled = 1
                continue
            if compiled == 0:
                result = re.match('\s*([^:]+):\s*(.+)', i.strip())
                if result:
                    dict[result.group(1)] = result.group(2)
            else:
                result = re.match('\s*-D\s*([^=]+)=?"?([^"\s]*)"?', i.strip())
                if result:
                    dict[result.group(1)] = result.group(2)
        return dict

    def get_conf(self):
        """
        :returns: configuration path location
        HTTPD_ROOT/SERVER_CONFIG_FILE
        """
        # rmme 2016-09-01
        # distro = platform.linux_distribution()[0].lower()
        # if distro == 'debian' or distro == 'ubuntu':
        #     phpfpm_name = "php5-fpm"
        # else:
        #     phpfpm_name = "php-fpm"
        phpfpm_process = self.daemon  # phpfpm_process["cmd"][0]
        if phpfpm_process:
            # the cmd line looks like:
            #   php-fpm: master process (/etc/php-fpm.conf)
            result = re.search('\((\S+)\)', phpfpm_process["cmd"])
            if result:
                return(result.group(1))
            # if the cmdline doesn't have the conf,
            # try to get the line from /etc/init.d/php5-fpm containing
            # --fpm-config and use the file name following it.
            try:
                searchfile = open("/etc/init.d/php5-fpm", "r")
            except:
                sys.stderr.write("php-fpm error: Failed to get configuration "
                                 "from init file.\n")
                error_collection.append("php-fpm error: Failed to get "
                                        "configuration from init file.\n")
                sys.exit(1)
            for line in searchfile:
                if "--fpm-config" in line:
                    result = re.search('--fpm-config\s+(\S+)', line)
                    if result:
                        return(result.group(1))

        sys.stderr.write("php-fpm error: Failed to get configuration.\n")
        error_collection.append("php-fpm error: Failed to get configuration.\n")
        sys.exit(1)

    def parse_config(self, wholeconfig):
        stanza_chain = []
        linenum = 0
        filechain = []
        stanzas = {}  # AutoVivification()
        # rmme 2016-09-01
        # server_keywords = ["listen", "root", "ssl_prefer_server_ciphers",
        #                    "ssl_protocols", "ssl_ciphers", "pm",
        #                    "pm.max_children", "pm.start_servers",
        #                    "pm.min_spare_servers", "pm.max_spare_servers"
        #                    ]
        # server_keywords_split = ["server_name"]
        for line in wholeconfig.splitlines():
            linenum += 1
            linecomp = line.strip().lower()
            # When we start or end a file, we inserted ## START or END so we
            # could identify the file in the whole config as they are opened.
            # We add them to a list, and remove them as they close.
            # Then we can use their name to identify where it is configured.
            filechange = re.match("## START (.*)", line)
            if filechange:
                filechain.append(filechange.group(1))
                # continue
            filechange = re.match("## END (.*)", line)
            if filechange:
                filechain.pop()
                # continue
            # stanza change
            result = re.match('[;#]', linecomp)
            if result:
                continue
            result = re.match('\[(\S+)\]', linecomp)
            if result:
                # the previous one ends when the new one starts
                # end
                if len(stanza_chain) > 0:
                    stanza_chain.pop()
                # start
                stanza_chain.append({"linenum": linenum, "title": result.group(1)})
            else:
                # match not spaces or =, then match = and spaces, then not spaces
                result = re.match('([^=\s]+)\s*=\s*(\S+)', linecomp)
                if result:
                    key = result.group(1)
                    value = result.group(2)
                    if not stanza_chain[-1]["title"] in stanzas:
                        stanzas[stanza_chain[-1]["title"]] = {}
                    stanzas[stanza_chain[-1]["title"]][key] = value
        stanzas["maxprocesses"] = 0
        for one in stanzas:
            if type(stanzas[one]) is dict:
                if stanzas.get(one, {}).get("pm.max_children"):
                    stanzas["maxprocesses"] += int(stanzas[one]["pm.max_children"])
        return(stanzas)


class MagentoCtl(object):
    def figlet(self):
        print """
 __  __                        _
|  \/  | __ _  __ _  ___ _ __ | |_ ___
| |\/| |/ _` |/ _` |/ _ \ '_ \| __/ _ \\
| |  | | (_| | (_| |  __/ | | | || (_) |
|_|  |_|\__,_|\__, |\___|_| |_|\__\___/
              |___/
"""

    def m1_parse_version(self, mage_php_file):
        """Parse version information from Mage.php from Magento 1.x
        mage_php_file is the path and filename of Mage.php"""
        mage = {}
        file_handle = open(mage_php_file, 'r')
        for line in file_handle:
            result = re.match("static\s+private\s+\$_currentEdition\s*=\s*self::([^\s;]+);",
                              line.strip(), re.IGNORECASE)
            if result:
                mage["edition"] = result.group(1)
            if "public static function getVersionInfo()" in line:
                line = file_handle.next()  # {
                line = file_handle.next()  # return array(
                while ");" not in line:
                    line = file_handle.next()
                    result = re.match("'([^']+)'\s*=>\s*'([^']*)'", line.strip())
                    if result:
                        mage[result.group(1)] = result.group(2)
                # break
        file_handle.close()
        # join them with periods, unless they are empty, then omit them
        mage["version"] = ".".join(filter(None,
                                          [mage.get("major"),
                                           mage.get("minor"),
                                           mage.get("revision"),
                                           mage.get("patch"),
                                           mage.get("stability"),
                                           mage.get("number")
                                           ]
                                          )
                                   )
        # This is to address 1.10.1.1 EE that has no $_currentEdition defined
        if "edition" not in mage:
            mage["edition"] = ""
        return(mage)

    def m2_parse_version(self, composer_json_file):
        """Parse version information from composer.json from Magento 2.x
        composer_json_file is the path and filename of composer.json"""
        # mage = {"edition": "", "version": ""}
        file_handle = open(composer_json_file, 'r')
        composer = json.load(file_handle)
        # print "%r" % composer

        mage = {}
        update(mage, composer)

        # This is not needed since we merged them immediately above
        # mage["version"] = composer.get(
        #   "version","No version string in composer.json")

        if "version" not in mage:
            mage["version"] = "No version string in composer.json"
        # This is to address 1.10.1.1 EE that has no $_currentEdition defined
        if "enterprise" in composer.get("name"):
            mage["edition"] = "Enterprise Edition"
        elif "community" in composer.get("name"):
            mage["edition"] = "Community Edition"
        else:
            mage["edition"] = composer.get("name", "No name String in composer.json")
        return(mage)

    def localxml(self, local_xml_file):
        pass

    def find_magento(self, doc_roots):
        # returns the key docroots and value full path and filename or
        #   Mage.php or magento
        # rmme 2016-09-01
        # pp = pprint.PrettyPrinter(indent=4)

        # print "854 magento docroots %r" % doc_roots
        return_dict = {}
        for doc_root_path in doc_roots:
            # with nginx and apache, we have docroot for web paths
            # we need to search those for Mage.php and local.xml
            # magento = MagentoCtl()
            # search_path = one # docroot
            mage_php_matches = []
            magento_exe_matches = []
            for root, dirnames, filenames in os.walk(doc_root_path):
                for filename in fnmatch.filter(filenames, 'Mage.php'):
                    mage_php_matches.append(os.path.join(root, filename))
                for filename in fnmatch.filter(filenames, 'magento'):
                    magento_exe_matches.append(os.path.join(root, filename))
            # print "957 magento_exe_matches"
            # pp.pprint(magento_exe_matches)
            # print "959 mage_php_matches"
            # pp.pprint(mage_php_matches)

            # Magento 1 first,
            # Is there more than one Magento 1 install in this path?
            if len(mage_php_matches) > 1:
                sys.stderr.write("WARNING: There are multiple Mage.php files "
                                 "in the Document Root %s. Choosing the "
                                 "shortest path.\n" % doc_root_path)
                error_collection.append("Magento error: There are multiple "
                                        "Mage.php files in the Document Root "
                                        "%s. Choosing the shortest path.\n" %
                                        doc_root_path)
                smallest_size = 0
                smallest_line = ""
                for i in mage_php_matches:
                    num_slashes = len(re.findall('/', i))
                    if smallest_size == 0:
                        smallest_size = num_slashes
                        smallest_line = i
                    elif num_slashes < smallest_size:
                        smallest_size = num_slashes
                        smallest_line = i
                mage_php_matches[0] = smallest_line
            # and if we found a magento path, lets add it to the return
            if mage_php_matches:
                return_dict[doc_root_path] = mage_php_matches[0]

            # Magento 2
            if len(magento_exe_matches) > 1:
                sys.stderr.write("WARNING: There are multiple bin/magento "
                                 "files in the Document Root %s. Choosing the "
                                 "shortest path.\n" % doc_root_path)
                error_collection.append("Magento error: There are multiple "
                                        "bin/magento files in the Document "
                                        "Root %s. Choosing the shortest path.\n"
                                        % doc_root_path)
                smallest_size = 0
                smallest_line = ""
                for i in magento_exe_matches:
                    num_slashes = len(re.findall('/', i))
                    if smallest_size == 0:
                        smallest_size = num_slashes
                        smallest_line = i
                    elif num_slashes < smallest_size:
                        smallest_size = num_slashes
                        smallest_line = i
                magento_exe_matches[0] = smallest_line
            if magento_exe_matches:
                magento_bin_path, bin_magento = os.path.split(magento_exe_matches[0])
                magento_path, magento_bin_dir = os.path.split(magento_bin_path)
                # print "934 bin path %s" % magento_bin_path
                # print "935 path %s" % magento_path
                return_dict[doc_root_path] = magento_exe_matches[0]
        # print "908 find_magento dict %r" % return_dict
        return(return_dict)

    def mage_file_info(self, mage_php_file):
        """Magento installation information"""
        return_dict = {}
        # get the dir name of the magento file
        # get the path and the last directory element
        mage_php_path, mage_php = os.path.split(mage_php_file)
        mage_path, path_tail = os.path.split(os.path.dirname(mage_php_file))
        # print ("944 php_file %s" % (mage_php_file))
        # print ("mage_path %s" % (mage_path))
        # print ("mage_php %s" % (mage_php))
        # print ("tail %s" % (mage_php))

        # Mage 1
        if mage_php == "Mage.php":
            mage = self.m1_parse_version(mage_php_file)
            return_dict["Mage.php"] = mage_php_file
            return_dict["magento_path"] = mage_path
            return_dict["local_xml"] = {}
            return_dict["local_xml"]["filename"] = os.path.join(mage_path,
                                                                "app",
                                                                "etc",
                                                                "local.xml")
            return_dict["magento_version"] = "%s" % mage["version"]
            if mage["edition"]:
                return_dict["magento_version"] += " %s" % mage["edition"]
            return_dict["mage_version"] = mage

        # Mage 2 looking for bin/magento
        if mage_php == "magento" and path_tail == "bin":
            return_dict["bin_magento"] = mage_php_file
            return_dict["magento_path"] = mage_path

            return_dict["composer_json"] = {}
            return_dict["composer_json"]["filename"] = os.path.join(mage_path, "composer.json")

            mage = self.m2_parse_version(return_dict["composer_json"]["filename"])
            # contains version and edition among others
            update(return_dict["composer_json"], mage)

            return_dict["env_php"] = {}
            return_dict["env_php"]["filename"] = os.path.join(mage_path,
                                                              "app",
                                                              "etc",
                                                              "env.php")

            # dummy data
            return_dict["magento_version"] = "%s" % mage["version"]
            if mage["edition"]:
                return_dict["magento_version"] += " %s" % mage["edition"]
            return_dict["Mage.php"] = mage_php_file
            return_dict["magento_path"] = mage_path

        return(return_dict)

    def mage2_config_gather(self, doc_root):
        """
        Provide the doc_root
        globalconfig["magento"]["doc_root"][doc_root_path]

        Parse env.php through php to json, then import json
        globalconfig["magento"]["doc_root"][doc_root_path]["env_php"]["filename"]

        return the dict so it can be put in
        globalconfig["magento"]["doc_root"][doc_root_path]["env_php"]

        doc_root["env_php"]
        """
        env_php_filename = doc_root["env_php"]["filename"]
        cmdline = "php -r 'print json_encode(require(\"%s\"));'" % env_php_filename
        p = subprocess.Popen(cmdline,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        else:
            # print "============================="
            composer = json.loads(output)
            # pp = pprint.PrettyPrinter(indent=4)
            # pp.pprint(composer)
            return(composer)
        """
        {   u'MAGE_MODE': u'production',
            u'backend': {   u'frontName': u'admin'},
            u'cache_types': {   u'block_html': 1,
                                u'collections': 1,
                                u'config': 1,
                                u'config_integration': 1,
                                u'config_integration_api': 1,
                                u'config_webservice': 1,
                                u'db_ddl': 1,
                                u'eav': 1,
                                u'full_page': 1,
                                u'layout': 1,
                                u'reflection': 1,
                                u'target_rule': 1,
                                u'translate': 1},
            u'crypt': {   u'key': u'11111111111111111111111'},
            u'db': {   u'connection': {   u'default': {   u'active': u'1',
                                                          u'dbname': u'stage',
                                                          u'host': u'10.1.2.3',
                                                          u'password': u'password',
                                                          u'username': u'username'},
                                          u'indexer': {   u'active': u'1',
                                                          u'dbname': u'stage',
                                                          u'host': u'10.139.52.37',
                                                          u'password': u'password',
                                                          u'persistent': None,
                                                          u'username': u'username'}},
                       u'table_prefix': u''},
            u'install': {   u'date': u'Thu, 10 Dec 2015 16:01:40 +0000'},
            u'resource': {   u'default_setup': {   u'connection': u'default'}},
            u'session': {   u'save': u'files'},
            u'x-frame-options': u'SAMEORIGIN'}
        """

    def open_local_xml(self, doc_root, config_node):
        """
        provide the filename (absolute or relative) of local.xml
        This function opens the file as an XML ElementTree
        returns: dict with db and cache information
        """
        filename = config_node["local_xml"]["filename"]
        try:
            tree = ET.ElementTree(file=filename)
        except IOError:
            sys.stderr.write("Could not open file %s\n" % filename)
            return()
        except ExpatError:
            sys.stderr.write("XML error parsing file %s\n" % filename)
            return()
        local_xml = {}

        # DATABASE
        section = "db"
        xml_parent_path = 'global/resources'
        xml_config_node = 'db/table_prefix'
        xml_config_section = 'default_setup/connection'
        update(local_xml, self.parse_local_xml(tree,
                                               section,
                                               xml_parent_path,
                                               xml_config_node,
                                               xml_config_section))

        # SESSION CACHE
        section = "session_cache"
        xml_parent_path = 'global'
        xml_config_node = 'session_save'
        xml_config_section = 'redis_session'
        xml_config_single = 'session_save_path'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path,
                                               xml_config_node,
                                               xml_config_section,
                                               xml_config_single='session_save_path'))
        # test for session cache redis
        resources = tree.find("global/redis_session")
        if resources is not None or (local_xml.get(section, {}).get(xml_config_node, "").lower() == "redis" and
                                     "tcp://" in local_xml.get(section, {}).get(xml_config_single, "")):
            local_xml[section]["engine"] = "redis"
            redis_module_xml = os.path.join(config_node["magento_path"], "app",
                                            "etc", "modules",
                                            "Cm_RedisSession.xml")
            # print "908 redis module xml: %s" % redis_module_xml
            # app/etc/modules/Cm_RedisSession.xml
            # xml config/modules/Cm_RedisSession/active
            try:
                # print "969 Cm_RedisSession check"
                redis_tree = ET.ElementTree(file=redis_module_xml)
                Cm_RedisSession = redis_tree.find("modules/Cm_RedisSession/active")
                if Cm_RedisSession is not None:
                    # print "opened Cm_RedisSession.xml"
                    if Cm_RedisSession.text is not None:
                        # print "and found %s" % Cm_RedisSession.text
                        local_xml[section]["Cm_RedisSession.xml active"] = Cm_RedisSession.text
                    else:
                        local_xml[section]["Cm_RedisSession.xml active"] = "Cm_RedisSession is present but the value is empty"
                else:
                    local_xml[section]["Cm_RedisSession.xml active"] = "Cm_RedisSession is not present"
            except IOError:
                error_collection.append("The file %s could not be opened." % redis_module_xml)
                local_xml[section]["Cm_RedisSession.xml active"] = "File not found"
        elif local_xml.get(section, {}).get(xml_config_node, "").lower() == "memcache":
            local_xml[section]["engine"] = "memcache"
        else:
            local_xml[section]["engine"] = "unknown"

        # OBJECT CACHE
        section = "object_cache"
        xml_parent_path = 'global/cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path,
                                               xml_config_node,
                                               xml_config_section))
        if local_xml.get(section, {}).get(xml_config_node, "").lower() == "mage_cache_backend_redis":
            local_xml[section]["engine"] = "redis"  # Magento's redis module
        elif local_xml.get(section, {}).get(xml_config_node, "").lower() == "cm_cache_backend_redis":
            local_xml[section]["engine"] = "redis"  # Colin M's redis module
        elif local_xml.get(section, {}).get(xml_config_node, "").lower() == "memcached":
            xml_parent_path = 'global/cache'
            xml_config_node = 'backend'
            xml_config_section = 'memcached/servers/server'
            update(local_xml, self.parse_local_xml(tree, section,
                                                   xml_parent_path,
                                                   xml_config_node,
                                                   xml_config_section))
            local_xml[section]["engine"] = "memcache"
            """
            global/cache/    memcached/servers/server
                    <memcached><!-- memcached cache backend related config -->
            <servers><!-- any number of server nodes can be included -->
                <server>
                    <host><![CDATA[]]></host>
                    <port><![CDATA[]]></port>
                    <persistent><![CDATA[]]></persistent>
                    <weight><![CDATA[]]></weight>
                    <timeout><![CDATA[]]></timeout>
                    <retry_interval><![CDATA[]]></retry_interval>
                    <status><![CDATA[]]></status>
                </server>
            </servers>
            """
        else:
            local_xml[section]["engine"] = "unknown"

        # FULL PAGE CACHE (FPC)
        section = "full_page_cache"
        xml_parent_path = 'global/full_page_cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        xml_config_single = 'slow_backend'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path,
                                               xml_config_node,
                                               xml_config_section,
                                               xml_config_single='slow_backend'))
        if local_xml.get(section, {}).get(xml_config_node, "").lower() == "mage_cache_backend_redis":
            local_xml[section]["engine"] = "redis"  # Magento's redis module
        elif local_xml.get(section, {}).get(xml_config_node, "").lower() == "cm_cache_backend_redis":
            local_xml[section]["engine"] = "redis"  # Colin M's redis module
        elif local_xml.get(section, {}).get(xml_config_node, "").lower() == "memcached":
            local_xml[section]["engine"] = "memcache"  # Colin M's redis module
        else:
            local_xml[section]["engine"] = "unknown"
        return(local_xml)

    def parse_local_xml(self, tree, section, xml_parent_path, xml_config_node, xml_config_section, **kwargs):
        """
        provide:
            tree, ElementTree object
            section, string, name of section
            xml_parent_path, string, section of xml where information is
            xml_config_node, string, node name that describes the type
            xml_config_section, section of additional nodes and text contents
            xml_config_single, string of a single additional node under parent
        returns a dict with key named "section"
        """
        local_xml = {}
        # full page cache (FPC) - redis
        # section = "full_page_cache"
        # xml_parent_path = 'global/full_page_cache'
        # xml_config_node = 'backend'
        # xml_config_section = 'backend_options'
        if "xml_config_single" in kwargs:
            xml_config_single = kwargs["xml_config_single"]
        else:
            xml_config_single = ""
        if section not in local_xml:
            local_xml[section] = {}
        resources = tree.find(xml_parent_path)
        if resources is not None:
            i = resources.find(xml_config_node)
            if i is not None:
                if i.text is not None:
                    local_xml[section][xml_config_node] = i.text
            if resources.find(xml_config_section) is not None:
                for i in resources.find(xml_config_section):
                    local_xml[section][i.tag] = i.text
            if xml_config_single:
                if resources.find(xml_config_single) is not None:
                    i = resources.find(xml_config_single)
                    local_xml[section][i.tag] = i.text
        return local_xml

    def db_cache_table(self, doc_root, value):
        """
        for doc_root, doc_root_dict in globalconfig["magento"]["doc_root"].iteritems():
            db_cache_table(doc_root,
                            doc_root_dict.get("local_xml", {}).get("db", {}))
        """
        mysql = MysqlCtl()
        # Some of these aren't used yet, BUT WILL BE. DO NOT REMOVE THEM
        var_table_prefix = value.get("db/table_prefix", "")
        var_dbname = value.get("dbname", "")
        # These will be needed if we use a db library in the future
        # var_host = value.get("host", "")
        # var_username = value.get("username", "")
        # var_password = value.get("password", "")
        output = mysql.db_query(value,
                                "select * FROM `%s`.`%score_cache_option`;" %
                                (var_dbname, var_table_prefix))
        # doc_root isn't used locally anymore? 14 Jan 2016
        # globalconfig["magento"]["doc_root"][doc_root]["cache"]["cache_option_table"]
        # doc_roots = globalconfig["magento"]["doc_root"]
        return_config = {}
        if not return_config.get("cache", {}).get("cache_option_table"):
            return_config = {"cache": {"cache_option_table": []}}
        return_config["cache"]["cache_option_table"] = output
        return(return_config)


class RedisCtl(object):
    def figlet(self):
        print """
              _ _
 _ __ ___  __| (_)___
| '__/ _ \/ _` | / __|
| | |  __/ (_| | \__ \\
|_|  \___|\__,_|_|___/
"""

    def get_status(self, ip, port, **kwargs):
        if not ip or not port:
            sys.stderr.write("ERROR, one of these is none, ip: %s port: %s\n" %
                             (ip, port))
            sys.exit(1)
        port = int(port)
        if kwargs.get("password") is not None:
            reply = socket_client(ip, port, ["AUTH %s\r\n" % kwargs["password"],
                                             "INFO\r\n"])
        else:
            reply = socket_client(ip, port, "INFO\r\n")
        if reply:
            return(reply)
        else:
            return(None)

    def parse_status(self, reply):
        return_dict = {}
        section = "none"
        for i in reply.splitlines():
            if len(i.strip()) == 0:
                continue
            if i.lstrip()[0] == "#":   # IndexError: string index out of range
                section = i.lstrip(' #').rstrip()
                if section not in return_dict:
                    return_dict[section] = {}
                continue
            try:
                [key, value] = i.split(':', 2)
            except ValueError:
                key = None
                value = None
            if key and value:
                key = key.strip()
                value = value.strip()
                if section not in return_dict:
                    return_dict[section] = {}
                return_dict[section][key] = value
                return_dict[key] = value
        return(return_dict)

    def get_all_statuses(self, instances, **kwargs):
        return_dict = {}
        for i in instances:
            host = instances[i]["host"]
            port = instances[i]["port"]
            password = instances.get(i, {}).get("password")
            if not return_dict.get(i):
                return_dict[i] = {}
            if password and host and port:
                reply = self.get_status(host, port, password=password)
            elif host and port:
                reply = self.get_status(host, port)
            else:
                reply = None
            if reply:
                return_dict[i] = self.parse_status(reply)
        return(return_dict)

    def instances(self, doc_roots):
        """
        With a list of doc_roots, examine the local xml we already parsed
        Make a list of redis instances, return the IP or hostname, port and
            password (password as applicable)
        Returns a dict of "host:port": {"host": "", "port": "", "password":""}
        Value is None if it is undefined
        Previously, a list of "host:port" was returned.
        You could iterate for i in instances().
        The return was changed to a dict, and the key is "host:port" so for i in
            instances() will still work,
        With the added benefit that you can now get to the values directly.
        """
        # redis_instances = set()
        redis_dict = {}  # "host:port": {host:"", port:"", password:""}
        for doc_root, doc_root_dict in doc_roots.iteritems():

            ################################################
            # Mage 1
            # if value.get("local_xml"):  # 2016-09-08
            local_xml = doc_root_dict.get("local_xml", {})
            # print "1179 local_xml"
            # pp.pprint(local_xml)

            # SESSION Mage 1
            local_session = local_xml.get("session_cache", {})
            if local_session.get("engine") == "redis":
                if (local_session.get("host") and
                        local_xml.get("session_cache", {}).get("port")):
                    # print "1182 session_cache is redis"
                    stanza = "%s:%s" % (
                        local_xml.get("session_cache", {}).get("host"),
                        local_xml.get("session_cache", {}).get("port")
                    )
                    # redis_instances.add(stanza)
                    if stanza not in redis_dict:
                        redis_dict[stanza] = {}
                    # if local_xml.get("session_cache", {}).get("host"):
                    redis_dict[stanza]["host"] = local_session.get("host")
                    # if local_xml.get("session_cache", {}).get("port"):
                    redis_dict[stanza]["port"] = local_session.get("port")
                    redis_dict[stanza]["password"] = local_session.get("password")
                    # print "1098 redis_dict %r" % redis_dict
                elif "tcp://" in local_session.get("session_save_path"):
                    result = re.match('tcp://([^:]+):(\d+)',
                                      local_session.get("session_save_path")
                                      )
                    if result:
                        host = result.group(1)
                        port = result.group(2)
                        stanza = "%s:%s" % (host, port)
                        if stanza not in redis_dict:
                            redis_dict[stanza] = {}
                        redis_dict[stanza]["host"] = host
                        redis_dict[stanza]["port"] = port
                        redis_dict[stanza]["password"] = None

            # OBJECT Mage 1
            local_object = local_xml.get("object_cache", {})
            # for this doc_root, if the object cache is memcache, get the ip and
            #   port, and add it to the set redis
            if local_object.get("engine") == "redis":
                # print "1200 object_cace is redis"
                stanza = "%s:%s" % (
                    local_xml.get("object_cache", {}).get("server"),
                    local_xml.get("object_cache", {}).get("port")
                )
                # redis_instances.add(stanza)
                if stanza not in redis_dict:
                    redis_dict[stanza] = {}
                redis_dict[stanza]["host"] = local_object.get("server")
                redis_dict[stanza]["port"] = local_object.get("port")
                redis_dict[stanza]["password"] = local_object.get("password")
                # print "1115 redis_dict %r" % redis_dict

            # FULL PAGE CACHE Mage 1
            local_fpc = local_xml.get("full_page_cache", {})
            # redis
            if local_fpc.get("engine") == "redis":
                stanza = "%s:%s" % (
                    local_fpc.get("server"),
                    local_fpc.get("port")
                )
                # redis_instances.add(stanza)
                if stanza not in redis_dict:
                    redis_dict[stanza] = {}
                # if local_xml.get("session_cache", {}).get("host"):
                redis_dict[stanza]["host"] = local_fpc.get("server")
                # if local_xml.get("session_cache", {}).get("port"):
                redis_dict[stanza]["port"] = local_fpc.get("port")
                redis_dict[stanza]["password"] = local_fpc.get("password")
                # print "1131 redis_dict %r" % redis_dict
            # if redis_dict:
            #     print "redis_dict:"
            #     pp.pprint(redis_dict)

            ################################################
            # Mage 2
            # the env_php, does it exist for this doc_root?
            env_php = doc_root_dict.get("env_php", {})
            # print "1447 env_php"
            # pp = pprint.PrettyPrinter(indent=4)
            # pp.pprint(env_php)

            env_session = env_php.get("session", {})
            # options for env_session["save"] == files or redis
            env_session_options = env_session.get("redis", {})
            # print "1454 env_session_options"
            # pp.pprint(env_session_options)

            # if (env_php.get("cache", {}).get("frontend", {}).get("page_cache",
            #                                                      {}) and
            #         env_fpc.get("backend") == "Cm_Cache_Backend_Redis"):
            if (env_session.get("save") == "redis"):
                # print "1454 redis save"
                if (env_session_options.get("host") and
                        env_session_options.get("port")):
                    # print "1182 session_cache is redis"
                    stanza = "%s:%s" % (env_session_options.get("host"),
                                        env_session_options.get("port"))
                    # print "1465 stanza: %s" % stanza
                    # could test to see if this redis is already there,
                    #   but I doubt it matters
                    if stanza not in redis_dict:
                        redis_dict[stanza] = {}
                    # if "session_cache" not in redis_dict[stanza]:
                    #     redis_dict[stanza]["session_cache"] = {}
                    # redis_dict[stanza]["host"] = env_session_options.get("host")
                    # redis_dict[stanza]["port"] = env_session_options.get("port")
                    # redis_dict[stanza]["password"] = env_session_options.get("password")
                update(redis_dict[stanza], env_session_options)

            env_fpc = env_php.get("cache", {}).get("frontend", {}).get("page_cache",
                                                                       {})
            env_fpc_options = env_fpc.get("backend_options", {})

            if (env_fpc.get("backend") == "Cm_Cache_Backend_Redis"):
                if (env_fpc_options.get("server") and
                        env_fpc_options.get("port")):
                    # print "1182 session_cache is redis"
                    stanza = "%s:%s" % (env_fpc_options.get("server"),
                                        env_fpc_options.get("port"))
                    # could test to see if this redis is already there,
                    #   but I doubt it matters
                    redis_dict[stanza] = {}
                    redis_dict[stanza]["host"] = env_fpc_options.get("server")
                    # redis_dict[stanza]["port"] = env_fpc_options.get("port")
                    # redis_dict[stanza]["password"] = env_fpc_options.get("password")
                update(redis_dict[stanza], env_fpc_options)

            env_default = env_php.get("cache", {}).get("frontend", {}).get("default", {})
            env_default_options = env_fpc.get("backend_options", {})

            # if (env_php.get("cache", {}).get("frontend", {}).get("page_cache", {}) and
            #         env_fpc.get("backend") == "Cm_Cache_Backend_Redis"):
            if (env_default.get("backend") == "Cm_Cache_Backend_Redis"):
                if (env_default_options.get("server") and env_default_options.get("port")):
                    # print "1182 session_cache is redis"
                    stanza = "%s:%s" % (env_default_options.get("server"),
                                        env_default_options.get("port"))
                    # could test to see if this redis is already there,
                    #   but I doubt it matters
                    redis_dict[stanza] = {}
                    redis_dict[stanza]["host"] = env_default_options.get("server")
                    # redis_dict[stanza]["port"] = env_default_options.get("port")
                    # redis_dict[stanza]["password"] = env_default_options.get("password")
                update(redis_dict[stanza], env_default_options)

        return(redis_dict)


class MemcacheCtl(object):
    def figlet(self):
        print """
                                         _
 _ __ ___   ___ _ __ ___   ___ __ _  ___| |__   ___
| '_ ` _ \ / _ \ '_ ` _ \ / __/ _` |/ __| '_ \ / _ \\
| | | | | |  __/ | | | | | (_| (_| | (__| | | |  __/
|_| |_| |_|\___|_| |_| |_|\___\__,_|\___|_| |_|\___|
"""

    def get_status(self, ip, port):
        port = int(port)
        reply = socket_client(ip, port, "stats\n")
        return(reply)

    def parse_status(self, reply):
        return_dict = {}
        # section = ""
        for i in reply.splitlines():
            if len(i.strip()) == 0:
                continue
            try:
                [STAT, key, value] = i.split(' ', 3)
            except ValueError:
                # STAT = None
                key = None
                value = None
            if key and value:
                key = key.strip()
                value = value.strip()
                return_dict[key] = value
        return(return_dict)

    def get_all_statuses(self, instances):
        return_dict = {}
        for instance in instances:
            [ip, port] = instance.split(":")
            if not return_dict.get(instance):
                return_dict[instance] = {}
            # print "1144 %r" % (instance)
            # need to check for a password
            reply = self.get_status(ip, port)
            return_dict[instance] = self.parse_status(reply)
        return(return_dict)

    def instances(self, doc_roots):
        # print "memcache.instances doc_roots: %r" % doc_roots
        return_dict = {}
        memcache_instances = set()
        for doc_root, doc_root_dict in doc_roots.iteritems():
            # for doc_root in doc_roots:
            #     doc_root_dict = globalconfig.get("magento", {}).get("doc_root", {}).get(doc_root, {})

            ################################################
            # Mage 1
            local_xml = doc_root_dict.get("local_xml", {})

            # SESSION Mage 1
            local_session = local_xml.get("session_cache", {})

            # for this doc_root, if the session cache is memcache, get the ip
            #   and port, and add it to the set memcache
            if local_session.get("engine") == "memcache":
                result = re.match('tcp://([^:]+):(\d+)',
                                  local_session.get("session_save_path")
                                  )
                if result:
                    host = result.group(1)
                    port = result.group(2)
                    stanza = "%s:%s" % (host, port)
                    return_dict[stanza] = {"host": host, "port": port}
                    memcache_instances.add(stanza)

            # OBJECT Mage 1
            local_object = local_xml.get("object_cache", {})
            # for this doc_root, if the object cache is memcache, get the ip and
            #   port, and add it to the set memcache
            if local_object.get("engine") == "memcache":
                host = local_object.get("host")
                port = local_object.get("port")
                stanza = "%s:%s" % (host, port)
                return_dict[stanza] = {"host": host, "port": port}
                memcache_instances.add(stanza)

            ################################################
            # Mage 2
            # the env_php, does it exist for this doc_root?
            env_php = doc_root_dict.get("env_php", {})
            # print "1447 env_php"
            # pp = pprint.PrettyPrinter(indent=4)
            # pp.pprint(env_php)

            # SESSION Mage 2
            env_session = env_php.get("session", {})
            # options for env_session["save"] == files or redis
            # print "1454 env_session_options"
            # pp.pprint(env_session_options)

            if (env_session.get("engine") == "memcache" or env_session.get("engine") == "memcached"):
                result = re.match('tcp://([^:]+):(\d+)',
                                  env_session.get("save_path")
                                  )
                if result:
                    host = result.group(1)
                    port = result.group(2)
                    stanza = "%s:%s" % (host, port)
                    return_dict[stanza] = {"host": host, "port": port}
                    memcache_instances.add(stanza)

        return(list(memcache_instances))
    """
Session Cache: memcache
session_save: memcache
session_save_path: tcp://172.24.16.131:11211?persistent=0&weight=2&timeout=10&retry_interval=10
[root@web2 EcommStatusTuning]# nc 172.24.16.131 11211
stats
STAT pid 27111
STAT uptime 37578201
STAT time 1447272815
STAT version 1.4.4
STAT pointer_size 64
STAT rusage_user 1843.374764
STAT rusage_system 2464.716306
STAT curr_connections 14
STAT total_connections 15313369
STAT connection_structures 313
STAT cmd_get 24296895
STAT cmd_set 54920211
STAT cmd_flush 0
STAT get_hits 17648856
STAT get_misses 6648039
STAT delete_misses 8116
STAT delete_hits 326720
STAT incr_misses 9402106
STAT incr_hits 14894789
STAT decr_misses 0
STAT decr_hits 0
STAT cas_misses 0
STAT cas_hits 0
STAT cas_badval 0
STAT auth_cmds 0
STAT auth_errors 0
STAT bytes_read 74468698360
STAT bytes_written 102428160453
STAT limit_maxbytes 524288000
STAT accepting_conns 1
STAT listen_disabled_num 0
STAT threads 4
STAT conn_yields 0
STAT bytes 1607968
STAT curr_items 715
STAT total_items 40465881
STAT evictions 0
END
    """


class MysqlCtl(object):
    def figlet(self):
        print """
 __  __       ____   ___  _
|  \/  |_   _/ ___| / _ \| |
| |\/| | | | \___ \| | | | |
| |  | | |_| |___) | |_| | |___
|_|  |_|\__, |____/ \__\_\_____|
        |___/
"""

    def get_status(self, ip, port):
        port = int(port)
        reply = socket_client(ip, port, "stats\n")
        return(reply)

    def db_query(self, dbConnInfo, sqlquery):
        """
        for doc_root, doc_root_dict in globalconfig["magento"]["doc_root"].iteritems():
            db_cache_table(doc_root,
                            doc_root_dict.get("local_xml", {}).get("db", {}))
            db_query(doc_root_dict.get("local_xml", {}).get("db", {}),
                     sqlquery)
        """
        # dbConnInfo = { "db/table_prefix", "dbname", "host", "username", "password" }
        # output = ""
        # flake8 lies. DO NOT REMOVE table_prefix
        # var_table_prefix = dbConnInfo.get("db/table_prefix", "")
        var_dbname = dbConnInfo.get("dbname", "")
        var_host = dbConnInfo.get("host", "")
        var_username = dbConnInfo.get("username", "")
        var_password = dbConnInfo.get("password", "")
        if (var_dbname and var_host and var_username and var_password):
            # conf = ("mysql --table --user='%s' --password='%s' --host='%s' "
            #         "--execute='%s' 2>&1 " % (var_username,
            #                                   var_password,
            #                                   var_host,
            #                                   sqlquery
            #                                   )
            #         )
            # sys.stderr.write("Querying MySQL...\n") # fixme --verbose?
            # p = subprocess.Popen(
            #     conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            #     shell=True)
            # output, err = p.communicate()
            # if p.returncode > 0 or not output:
            #     return()
            #     sys.stderr.write("MySQL cache table query failed\n")
            #     error_collection.append("MySQL cache table query failed: %s\n" %
            #                             conf)
            #     if err:
            #         sys.stderr.write("err %s\n" % err)
            #         error_collection.append("err %s\n" % err)
            #     try:
            #         sys.stderr.write("command: %s\n" % conf)
            #         error_collection.append("command: %s\n" % conf)
            #     except UnicodeEncodeError:
            #         pass
            # testing mysql connector
            config = {
                'user': var_username,
                'password': var_password,
                'host': var_host,
                'database': var_dbname,
                'raise_on_warnings': True,
            }
            try:
                cnx = mysql.connector.connect(**config)
                cursor = cnx.cursor()
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                    print("Something is wrong with your user name or password")
                elif err.errno == errorcode.ER_BAD_DB_ERROR:
                    print("Database does not exist")
                else:
                    print(err)
                    # sys.exit(1)  # fixme
                    sys.stderr.write("WARNING MySQL: %s.\n" % err)
                    error_collection.append("WARNING MySQL: %s.\n" % err)
                    """
Traceback (most recent call last):
 File "./ecomm-recon", line 515, in <module>
   doc_root_dict.get("local_xml", {}).get("db", {}))
 File "/root/stack-recon/stack-recon/stackreconlib.py", line 1374, in db_cache_table
   (var_dbname, var_table_prefix))
 File "/root/stack-recon/stack-recon/stackreconlib.py", line 1859, in db_query
   cursor.execute(sqlquery)
UnboundLocalError: local variable 'cursor' referenced before assignment
                    """
            # do stuff sqlquery
            cursor.execute(sqlquery)
            return_list = cursor.fetchall()
            for (i, j) in cursor:
                # print("%s - %s" % (i, j))
                pass
            cnx.close()
        # else:
            # print "Skipping database because there isn't enough login information"
            # print " Table prefix: %s" % var_table_prefix
            # print " dbname: %s" % var_dbname
            # print " host: %s" % var_host
            # print " username: %s" % var_username
            # if var_password:
            #     print " password present but not displayed"
            # print " password: %s" % var_password
        # print
        # return(output)
        return(return_list)

    def parse_key_value(self, queried_table):
        lines = queried_table.splitlines()
        lines = input.splitlines()
        counter = 0
        for line in lines:
            return_dict = {}
            # skip X lines
            if counter < 3:
                counter += 1
                continue
            counter += 1
            result = re.search('\|\s*([^\|]+)\|\s*([^\|]+)', line)
            if not result:
                print "done"
                break
            return_dict[result.group(1).strip()] = result.group(2).strip()
        return(return_dict)

    def not_used_instances(self, doc_roots):
        """
        With a list of doc_roots, examine the local xml we already parsed
        Make a list of mysql instances, return the "db/table_prefix", "dbname", "host", "username", "password"
        Returns a dict
        Value is None if it is undefined
        globalconfig[
            "magento": {
                "doc_root": {
                    "/var/www/vhosts/www.example.com/html": {
                        "local_xml": {
                            "db": {
                                "dbname": "databasename",
                                "host": "172.24.16.2",
                                "password": "password",
                                "username": "someuser"
                            }
                        }
                    }
                }
            }
        ]
        """
        # redis_instances = set()
        # dbConnInfo = { "db/table_prefix", "dbname", "host", "username", "password" }
        return_dict = {}  # "host:port": {host:"", port:"", password:""}
        for doc_root in doc_roots:
            # we should not access the globalconfig variable in a function.
            # data: pass it in, pass it out
            if doc_roots.get(doc_root, {}).get("local_xml"):
                xml_db = doc_roots.get(doc_root, {}).get("local_xml", {}).get("db", {})
            return_dict[xml_db["host"]]["credentials"].add(xml_db)
            pass
        # globalconfig["mysql"]=return_dict
        return(return_dict)


def socket_client(host, port, string, **kwargs):
    if "TIMEOUT" in kwargs:
        timeout = int(kwargs["TIMEOUT"])
    else:
        timeout = 5
    if isinstance(string, basestring):
        strings = [string]
    else:
        strings = string
    # ip, port = '172.24.16.68', 6386
    # SOCK_STREAM == a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    # sock.setdefaulttimeout(timeout)
    # sock.setblocking(0)  # optional non-blocking
    try:
        sock.connect((host, int(port)))
        for string in strings:
            sock.send(string)
            reply = sock.recv(16384)  # limit reply to 16K
            # print "1352 reply %s" % reply
        sock.close()
    except socket.error:
        sys.stderr.write("socket connect error host: %s port: %s\n" % (host, port))
        error_collection.append("socket connect error host: %s port: %s" % (host, port))
        return(None)
    return reply


def daemon_exe(match_exe):
    """
    var_filter = "text to search with"
    using this as the filter will find an executable by name whether it was call by absolute path or bare
    "^(\S*/bash|bash)"
    """
    daemons = {}
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        psexe = ""
        ppid = ""
        pscmd = ""
        pserror = ""
        try:
            ppid = open(os.path.join('/proc', pid, 'stat'), 'rb').read().split()[3]
            pscmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read().replace("\000", " ").rstrip()
            # On one system, I have observed the exe linked to a filename
            #   with a * added at the end and this causes a TypeError
            psexe = os.path.realpath(os.path.join('/proc', pid, 'exe'))
        except TypeError:
            # e = ""
            sys.stderr.write("TypeError %s\n" % (os.path.join('/proc', pid, 'exe')))
            continue
        except (IOError, OSError):  # proc has already terminated, you may not be root
            continue
        else:
            # probably don't need the if psexe now 1-20-2016
            # if the exe has been deleted (i.e. through an rpm update), the exe will be "/usr/sbin/nginx (deleted)"
            if psexe:
                if re.search('\(deleted\)', psexe):
                    # if the exe has been deleted (i.e. through an rpm update), the exe will be "/usr/sbin/nginx (deleted)"
                    pserror = psexe
                    result = re.match('([^\(]+)', psexe)
                    psexe = result.group(1).rstrip()
                    pass
                if os.path.basename(psexe) in match_exe:
                    # if os.path.basename(psexe) == daemon_name:
                    if ppid == "1" or not os.path.basename(psexe) in daemons:
                        daemons[os.path.basename(psexe)] = {"exe": "", "cmd": "", "basename": ""}
                        daemons[os.path.basename(psexe)]["exe"] = psexe
                        daemons[os.path.basename(psexe)]["cmd"] = pscmd
                        daemons[os.path.basename(psexe)]["basename"] = os.path.basename(psexe)
                        if pserror:
                            daemons[os.path.basename(psexe)]["error"] = "Process %s, %s is in (deleted) status. It may not exist, or may have been updated." % (pid, pserror)
                            pserror = ""
    return(daemons)


class AutoVivification(dict):
    """Implementation of perl's autovivification feature."""
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


def importfile(filename, keyword_regex, **kwargs):
    """
    pass the filename of the base config file, and a keyword regular expression to identify the include directive.
    The regexp should include parantheses ( ) around the filename part of the match
    keywords: base_path = "/some/path"
    trailing / will be stripped
    kwargs["base_path"] will be added to filename that do not include and absolute path. i.e. Apache includes
    Examples (the regexp is case insensitive):
    nginx
        wholeconfig = importfile(conffile, '\s*include\s+(\S+)')
    httpd
        wholeconfig = importfile(conffile, '\s*include\s+(\S+)', base_path="/etc/httpd")
    """
    # make the base_path incoming keyword a little more fault tolerant by
    #   removing the trailing slash
    if "base_path" in kwargs:
        base_path = kwargs["base_path"].rstrip("/")
    else:
        base_path = ""
    if "recurse_count" in kwargs:
        kwargs["recurse_count"] += 1
    else:
        kwargs["recurse_count"] = 0
    if kwargs["recurse_count"] > 20:
        # arbitrary number
        sys.stderr.write("Too many recursions while importing %s, the config "
                         "is probably a loop.\n" % filename)
        error_collection.append("Too many recursions while importing %s, the "
                                "config is probably a loop.\n" % filename)
        sys.exit(1)

    def full_file_path(right_file, base_path):
        # If the right side of the full name doesn't have a leading slash, it
        #   is a relative path.
        # Add the base_path to the left and return the value
        # else just return the name
        if right_file[0] not in "/":
            return(os.path.join(base_path, right_file))
        else:
            return(right_file)  # this is the fix!
    # either an absolute path to a file, or absolute path to a glob
    files = glob.glob(full_file_path(filename, base_path))
    combined = ""
    # print "1655 %r" % full_file_path(filename, base_path)
    # print "1656 %r" % files
    for onefile in files:
        # for each file in the glob (may be just one file), open it
        # try:
        onefile_handle = open(onefile, 'r')
        # print "1659 onefile_handle %r" % onefile_handle
        # onefile should always be a file
        if os.path.isfile(onefile):
            combined += "## START " + onefile + "\n"
        # else:
        #     print "1664 file isn't a file? " % onefile
        # except:
        #     return()
        # go through the file, line by line
        # if it has an include, go follow it
        for line in onefile_handle:
            result = re.match(keyword_regex, line.strip(), re.IGNORECASE)
            # if it is an include, remark out the line,
            # figure out the full filename
            # and import it inline
            if result:
                combined += "#" + line + "\n"
                nestedfile = full_file_path(result.group(1), base_path)
                combined += importfile(nestedfile, keyword_regex, **kwargs)
            else:
                combined += line
        # END of the file import, if it was a file and not a glob, make the ending.
        # onefile should always be a file
        if os.path.isfile(onefile):
            combined += "## END " + onefile + "\n"
        onefile_handle.close()
        # print "#combined#"
        # print combined
        # print "#end#"
    return(combined)


def kwsearch(keywords, line, **kwargs):
    """
    pass:
        a list of keywords
        a string to check for keywords and extract a value (the value is everything right of the keyword)
        optional: single_value=True returns a list of the values found, unless single_value is True
    """
    line = line.lower()
    stanza = {}
    for word in keywords:
        result = re.match("(%s)\s*(.*)" % word, line.strip(), re.IGNORECASE)
        # result = re.search("\s*(%s)\s*(.*)" % word, line.strip(), re.IGNORECASE)

        # this way, without the for loop took 10-12 times as long to run
        # result = re.search("\s*(%s)\s*(.*)" % '|'.join(map(str, keywords)), line.strip(), re.IGNORECASE)
        if result:
            if "single_value" not in kwargs:
                if not result.group(1).lower() in stanza:
                    stanza[result.group(1).lower()] = []
                if not result.group(2).strip('\'"') in stanza[result.group(1).lower()]:
                    if "split_list" not in kwargs:
                        stanza[result.group(1).lower()] += [result.group(2).strip(';"\'')]
                    else:
                        stanza[result.group(1).lower()] += [result.group(2).strip(';"\'').split()]
            else:
                stanza[result.group(1)] = result.group(2).strip('"\'')
    return(stanza)  # once we have a match, move on


def memory_estimate(process_name, **kwargs):
    """
    line_count 16
    biggest 17036
    free_mem 1092636
    line_sum 61348
    """
    status = {"line_sum": 0, "line_count": 0, "biggest": 0, "free_mem": 0,
              "buffer_cache": 0, "php_vsz-rss_sum": 0}
    # freeMem=`free|egrep '^Mem:'|awk '{print $4}'`
    conf = "free"
    p = subprocess.Popen(
        conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, err = p.communicate()
    if not output:
        raise NameError("Fail: %s" % err)
    lines_list = string.split(output, '\n')
    status["free_mem"] = int(lines_list[1].split()[4])
    status["buffer_cache"] = int(lines_list[2].split()[3])
    # print stuff[1].split()[1]
    # The calculation is using RSS, and free memory.
    # There are buffers and cache used by the process, and that throws off
    #   the calculation
    # for line in lines:
    #     result = re.match('(Mem:)\s+(\S+)\s+(\S+)\s+(\S+)', line)
    #     if result:
    #         status["free_mem"] = int(result.group(4))
    #         continue
    #     result = re.match('(\+/-\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
    #     if result:
    #         status["buffer_cache"] = int(result.group(4))
    #         # print "1552 buffer_cache"
    #         # print status["buffer_cache"]
    #         break
    conf = "ps aux | grep %s" % process_name
    p = subprocess.Popen(
        conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, err = p.communicate()
    if not output:
        raise NameError("Fail: %s" % err)
    for line in output.splitlines():
        status["line_count"] += 1
        result = re.match('\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+', line)
        if result:
            status["line_sum"] += int(result.group(6))
            status["php_vsz-rss_sum"] += (int(result.group(5)) - int(result.group(6)))
            if int(result.group(6)) > status["biggest"]:
                status["biggest"] = int(result.group(6))
    return(status)


def memory_print(result, proc_name, proc_max):
    print "%d %s processes are currently using %d KB of memory, and there is %d KB of free memory." % (
        result["line_count"],
        proc_name,
        result["line_sum"],
        result["free_mem"])
    print "Average memory per process: %d KB will use %d KB if max processes %d is reached." % (
        result["line_sum"] / result["line_count"],
        int(result["line_sum"] / result["line_count"] * proc_max),
        proc_max)
    print "Largest process: %d KB will use %d KB if max processes is reached.\n" % (
        result["biggest"],
        result["biggest"] * proc_max)
    print "What should I set max processes to?"
    print "The safe value would be to use the largest process, and commit 80%% of memory: %d" % int((result["line_sum"] + result["free_mem"]) / result["biggest"] * .8)
    print
    print "Current maximum processes: %d" % proc_max
    print "avg 100% danger   avg 80% warning   lrg 100% cautious   lrg 80% safe"
    print "     %3d                %3d                %3d              %3d" % (
        int(((result["line_sum"] + result["free_mem"]) / (result["line_sum"] / result["line_count"]))),
        int(((result["line_sum"] + result["free_mem"]) / (result["line_sum"] / result["line_count"])) * .8),
        int((result["line_sum"] + result["free_mem"]) / result["biggest"]),
        int((result["line_sum"] + result["free_mem"]) / result["biggest"] * .8)
    )


def print_sites(localconfig):
    for one in sorted(localconfig):
        if "domains" in one:
            print "Domains: %s" % "  ".join(one["domains"])
        if "listening" in one:
            print "listening: %s" % ", ".join(one["listening"])
        if "doc_root" in one:
            print "Doc root: %s" % one["doc_root"]
        if "config_file" in one:
            print "Config file: %s" % one["config_file"]
        if "access_log" in one:
            print "Access log: %s" % one["access_log"]
        if "error_log" in one:
            print "Error log: %s" % one["error_log"]
        print


def update(d, u):
    """
    update dictionary d with updated dictionary u recursively
    """
    # for k, v in u.iteritems():
    for k in u:
        # if isinstance(v, collections.Mapping):
        if isinstance(u[k], dict):
            r = update(d.get(k, {}), u[k])
            d[k] = r
        else:
            d[k] = u[k]
    return d


def print_table(table, **kwargs):
    """
    Provide a list of lists for the table
table = [
[ "row1col1", "row1col2", "row1col3"],
[ "row2col1", "row2col2", "row2col3"],
[ "row3col1", "row3col2", "row3col3"]
]

    if HEADER=True then divide the first line from the following lines
    if NOTABLE=True then no table, colon separated instead
    turn a dict in to a list with
    table = [(str(k), str(v)) for k, v in mydict.iteritems()]
    """

    # if NOTABLE is not set or NOTABLE is not True
    if kwargs.get("NOTABLE") is True:
        for line in table:
            # print "debug x %d, col_width[i] %d" % (x, col_width[i])
            print ": ".join(line)
    else:
        # Ugly workaround for unicode
        first_line = True
        try:
            col_width = [max(len(str(x)) for x in col) for col in zip(*table)]
            print "+-" + "-+-".join("{0:{1}}".format("-" * col_width[i], col_width[i])
                                    for i, x in enumerate(table[0])) + "-+"
            for line in table:
                # print "debug x %d, col_width[i] %d" % (x, col_width[i])
                print "| " + " | ".join("{0:{1}}".format(x, col_width[i])
                                        for i, x in enumerate(line)) + " |"
                if first_line is True and kwargs.get("HEADER") is True:
                    print "+-" + "-+-".join("{0:{1}}".format("-" * col_width[i], col_width[i])
                                            for i, x in enumerate(table[0])) + "-+"
                    first_line = False
            print "+-" + "-+-".join("{0:{1}}".format("-" * col_width[i], col_width[i])
                                    for i, x in enumerate(table[0])) + "-+"
        except UnicodeEncodeError:
            col_width = [max(len(x.encode('utf-8')) for x in col) for col in zip(*table)]
            print "+-" + "-+-".join("{0:{1}}".format("-" * col_width[i], col_width[i])
                                    for i, x in enumerate(table[0])) + "-+"
            for line in table:
                # print "debug x %d, col_width[i] %d" % (x, col_width[i])
                print "| " + " | ".join("{0:{1}}".format(x.encode('utf-8'), col_width[i])
                                        for i, x in enumerate(line)) + " |"
                if first_line is True and kwargs.get("HEADER") is True:
                    print "+-" + "-+-".join("{0:{1}}".format("-" * col_width[i], col_width[i])
                                            for i, x in enumerate(table[0])) + "-+"
                    first_line = False
            print "+-" + "-+-".join("{0:{1}}".format("-" * col_width[i], col_width[i])
                                    for i, x in enumerate(table[0])) + "-+"

"""
table = [
[ "row1col1", "row1col2", "row1col3"],
[ "row2col1", "row2col2", "row2col3"],
[ "row3col1", "row3col2", "row3col3"]
]
print_table(table)
"""


"""
Bytes-to-human / human-to-bytes converter.
Based on: http://goo.gl/kTQMs
Working with Python 2.x and 3.x.

Author: Giampaolo Rodola' <g.rodola [AT] gmail [DOT] com>
License: MIT
"""

# see: http://goo.gl/kTQMs
SYMBOLS = {
    'customary'     : ('B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'),
    'customary_ext' : ('byte', 'kilo', 'mega', 'giga', 'tera', 'peta', 'exa',
                       'zetta', 'iotta'),
    'iec'           : ('Bi', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi', 'Yi'),
    'iec_ext'       : ('byte', 'kibi', 'mebi', 'gibi', 'tebi', 'pebi', 'exbi',
                       'zebi', 'yobi'),
}


def bytes2human(n, format='%(value).1f %(symbol)s', symbols='customary'):
    """
    Convert n bytes into a human readable string based on format.
    symbols can be either "customary", "customary_ext", "iec" or "iec_ext",
    see: http://goo.gl/kTQMs

      >>> bytes2human(0)
      '0.0 B'
      >>> bytes2human(0.9)
      '0.0 B'
      >>> bytes2human(1)
      '1.0 B'
      >>> bytes2human(1.9)
      '1.0 B'
      >>> bytes2human(1024)
      '1.0 K'
      >>> bytes2human(1048576)
      '1.0 M'
      >>> bytes2human(1099511627776127398123789121)
      '909.5 Y'

      >>> bytes2human(9856, symbols="customary")
      '9.6 K'
      >>> bytes2human(9856, symbols="customary_ext")
      '9.6 kilo'
      >>> bytes2human(9856, symbols="iec")
      '9.6 Ki'
      >>> bytes2human(9856, symbols="iec_ext")
      '9.6 kibi'

      >>> bytes2human(10000, "%(value).1f %(symbol)s/sec")
      '9.8 K/sec'

      >>> # precision can be adjusted by playing with %f operator
      >>> bytes2human(10000, format="%(value).5f %(symbol)s")
      '9.76562 K'
    """
    try:
        n = int(n)  # fixme TypeError: int() argument must be a string or a number, not 'NoneType'
    except TypeError:
        sys.stderr.write("NOTICE: TypeError, int value expected.\n")
        error_collection.append("NOTICE: TypeError, int value expected.\n")
        return
    if n < 0:
        raise ValueError("n < 0")
    symbols = SYMBOLS[symbols]
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i+1)*10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)


def human2bytes(s):
    """
    Attempts to guess the string format based on default symbols
    set and return the corresponding bytes as an integer.
    When unable to recognize the format ValueError is raised.

      >>> human2bytes('0 B')
      0
      >>> human2bytes('1 K')
      1024
      >>> human2bytes('1 M')
      1048576
      >>> human2bytes('1 Gi')
      1073741824
      >>> human2bytes('1 tera')
      1099511627776

      >>> human2bytes('0.5kilo')
      512
      >>> human2bytes('0.1  byte')
      0
      >>> human2bytes('1 k')  # k is an alias for K
      1024
      >>> human2bytes('12 foo')
      Traceback (most recent call last):
          ...
      ValueError: can't interpret '12 foo'
    """
    init = s
    num = ""
    while s and s[0:1].isdigit() or s[0:1] == '.':
        num += s[0]
        s = s[1:]
    num = float(num)
    letter = s.strip()
    for name, sset in SYMBOLS.items():
        if letter in sset:
            break
    else:
        if letter == 'k':
            # treat 'k' as an alias for 'K' as per: http://goo.gl/kTQMs
            sset = SYMBOLS['customary']
            letter = letter.upper()
        else:
            raise ValueError("can't interpret %r" % init)
    prefix = {sset[0]:1}
    for i, s in enumerate(sset[1:]):
        prefix[s] = 1 << (i+1)*10
    return int(num * prefix[letter])
