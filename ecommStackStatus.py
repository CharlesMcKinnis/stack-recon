#!/usr/bin/env python2
"""
Magento is a trademark of Varien. Neither I nor these scripts are affiliated with or endorsed by the Magento Project or its trademark owners.

"""

"""
wget https://raw.githubusercontent.com/CharlesMcKinnis/ecommStackStatus/master/ecommStackStatus.py

git clone https://github.com/CharlesMcKinnis/ecommStackStatus.git
#dev branch
git checkout -b dev origin/dev
"""

"""
The script will look for apache, nginx and php-fpm binaries in memory, and identify their configuration source.
Using the web server config, the document root and domain information is collected and displayed
php-fpm configuration is collected and displayed

Using the document roots, it searches for Mage.php to identify Magento installations.

For each Magento installation, version and edition is collected from Mage.php
Configuration for database, and session, object and full page caches

The database (assumed to be MySQL) is queried for whether cache is enabled

If either redis or memcache is configured, it is queried via tcp for status information, that is collected and displayed

* things to add
We could get information similar to MySQL Buddy and display it, to name a few:
long_query_time
query_cache_size
join_buffer_size
table_open_cache
innodb_buffer_pool_size
innodb_buffer_pool_instances
innodb_log_buffer_size
query_cache_limit

* name json file by hostname and date+time

* I would like to load all xml in app/etc/ and overwrite values of local.xml so the config is complete

DONE
* also need to check, if session cache is using redis - DONE 
app/etc/modules/Cm_RedisSessions.xml
value of <active> to true
* add hostname in globalconfig


"""
STACK_STATUS_VERSION = 2015111202
error_collection = []

import re
import glob
import subprocess
import sys
import os
#import yaml
import fnmatch
try:
    import xml.etree.ElementTree as ET
except ImportError:
    import cElementTree as ET
import pprint
import socket
import collections
try:
    import json
    JSON = True
except ImportError:
    try:
        import simplejson
    except ImportError:
        JSON = False
        sys.stderr.write("Data export omitted, module json and simplejson are not installed\n")
        sys.stderr.write("This is most common on RHEL 5 with python 2.4. run: yum install python-simplejson")
        error_collection.append("Data export omitted because the json module is not installed\n")
try:
    import argparse
    ARGPARSE = True
except ImportError:
    ARGPARSE = False
    sys.stderr.write("This program is more robust if python argparse installed.\n")
    #error_collection.append("This program is more robust if python argparse installed.\n")
try:
    import mysql.connector
    MYSQL = True
except ImportError:
    MYSQL = False
    #sys.stderr.write("This program will be more robust if mysql.connector installed.\n")
    #error_collection.append("This program will be more robust if mysql.connector installed.\n")
    
class argsAlt(object):
    pass

class apacheCtl(object):
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        if not "exe" in self.kwargs:
            self.kwargs["exe"] = "httpd"
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
        version = self.kwargs["exe"]+" -v"
        p = subprocess.Popen(
            version, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
            )
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        else:
            return(output)

    def get_conf_parameters(self):
        conf = self.kwargs["exe"]+" -V 2>&1"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        dict = {}
        compiled=0
        for i in output.splitlines():
            if i.strip()=="Server compiled with....":
                compiled=1
                continue
            if compiled == 0:
                result = re.match('\s*([^:]+):\s*(.+)', i.strip())
                if result:
                    dict[result.group(1)]=result.group(2)
            else:
                result = re.match('\s*-D\s*([^=]+)=?"?([^"\s]*)"?', i.strip() )
                if result:
                    dict[result.group(1)]=result.group(2)
        return dict

    def get_root(self):
        try:
            return self.get_conf_parameters()['HTTPD_ROOT']
        except KeyError:
            sys.exit(1)

    def get_conf(self):
        """
        :returns: configuration path location
        HTTPD_ROOT/SERVER_CONFIG_FILE
        """
        try:
            return os.path.join(self.get_conf_parameters()['HTTPD_ROOT'],self.get_conf_parameters()['SERVER_CONFIG_FILE'])
        except KeyError:
            sys.exit(1)

    def get_mpm(self):
        try:
            return self.get_conf_parameters()['Server MPM']
        except KeyError:
            sys.exit(1)

    def parse_config(self,wholeconfig):
        """
        list structure
        { line : { listen: [ ], server_name : [ ], root : path } }
    
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
        location_start = 0
        linenum = 0
        filechain = []
        stanza_flags = []
        stanzas = {} #AutoVivification()
        base_keywords = ["serverroot", "startservers", "minspareservers", "maxspareservers", "maxclients", "maxrequestsperchild", "listen"]
        vhost_keywords = ["documentroot", "servername", "serveralias", "customlog", "errorlog", "transferlog", "loglevel", "sslengine", "sslprotocol", "sslciphersuite", "sslcertificatefile", "sslcertificatekeyfile", "sslcacertificatefile", "sslcertificatechainfile"]
        prefork_keywords = ["startservers", "minspareservers", "maxspareservers", "maxclients", "maxrequestsperchild", "listen", "serverlimit"]
        worker_keywords = ["startservers", "maxclients", "minsparethreads", "maxsparethreads", "threadsperchild", "maxrequestsperchild"]
        event_keywords = ["startservers", "minspareservers", "maxspareservers", "serverlimit", "threadsperchild", "maxrequestworkers", "maxconnectionsperchild", "minsparethreads", "maxsparethreads"]
        for line in wholeconfig.splitlines():
            linenum += 1
            linecomp = line.strip().lower()
            # when we start or end a file, we inserted ## START or END so we could identify the file in the whole config
            # as they are opened, we add them to a list, and remove them as they close.
            # then we can use their name to identify where it is configured
            filechange = re.match("## START (.*)",line)
            if filechange:
                filechain.append(filechange.group(1))
                if vhost_start == -1:
                    if not "config_file" in stanzas:
                        stanzas["config_file"] = []
                    stanzas["config_file"].append(filechange.group(1)) 
                continue
            filechange = re.match("## END (.*)",line)
            if filechange:
                filechain.pop()
                continue
            # listen, documentroot
            # opening VirtualHost
            result = re.match('<[^/]\s*(\S+)', linecomp )
            if result:
                stanza_count += 1
                stanza_chain.append({ "linenum" : linenum, "title" : result.group(1) })
            result = re.match('</', linecomp )
            if result:
                stanza_count -= 1
                stanza_chain.pop()
    
    
            # base configuration
            if stanza_count == 0:
                keywords = base_keywords + vhost_keywords
                if not "config" in stanzas:
                    stanzas["config"] = { }
                update(stanzas["config"], kwsearch(keywords,linecomp))
    
            # prefork matching
            result = re.match('<ifmodule\s+prefork.c', linecomp, re.IGNORECASE )
            if result:
                stanza_flags.append({"type" : "prefork", "linenum" : linenum, "stanza_count" : stanza_count})
                continue
            # prefork ending
            result = re.match('</ifmodule>', linecomp, re.IGNORECASE )
            if result:
                # you may encounter ending modules, but not have anything in flags, and if so, there is nothing in it to test
                if len(stanza_flags) > 0:
                    if stanza_flags[-1]["type"] == "prefork" and stanza_flags[-1]["stanza_count"] == stanza_count+1:
                        stanza_flags.pop()
                        continue
            # If we are in a prefork stanza
            if len(stanza_flags) > 0:
                if stanza_flags[-1]["type"] == "prefork" and stanza_flags[-1]["stanza_count"] == stanza_count:
                    if not "prefork" in stanzas:
                        stanzas["prefork"] = {}
                    update(stanzas["prefork"], kwsearch(prefork_keywords,line,single_value=True))
                    continue
    
            # worker matching
            result = re.match('<ifmodule\s+worker.c', linecomp, re.IGNORECASE )
            if result:
                stanza_flags.append({"type" : "worker", "linenum" : linenum, "stanza_count" : stanza_count})
            result = re.match('</ifmodule>', linecomp, re.IGNORECASE )
            if result:
                # you may encounter ending modules, but not have anything in flags, and if so, there is nothing in it to test
                if len(stanza_flags) > 0:
                    if stanza_flags[-1]["type"] == "worker" and stanza_flags[-1]["stanza_count"] == stanza_count+1:
                        stanza_flags.pop()
            # If we are in a prefork stanza
            if len(stanza_flags) > 0:
                if stanza_flags[-1]["type"] == "worker" and stanza_flags[-1]["stanza_count"] == stanza_count:
                    if not "worker" in stanzas:
                        stanzas["worker"] = {}
                    update(stanzas["worker"], kwsearch(worker_keywords,linecomp,single_value=True))
                    continue

            # event matching
            result = re.match('<ifmodule\s+mpm_event', linecomp, re.IGNORECASE )
            if result:
                stanza_flags.append({"type" : "event", "linenum" : linenum, "stanza_count" : stanza_count})
            result = re.match('</ifmodule>', linecomp, re.IGNORECASE )
            if result:
                # you may encounter ending modules, but not have anything in flags, and if so, there is nothing in it to test
                if len(stanza_flags) > 0:
                    if stanza_flags[-1]["type"] == "event" and stanza_flags[-1]["stanza_count"] == stanza_count+1:
                        stanza_flags.pop()
            # If we are in a prefork stanza
            if len(stanza_flags) > 0:
                if stanza_flags[-1]["type"] == "event" and stanza_flags[-1]["stanza_count"] == stanza_count:
                    if not "event" in stanzas:
                        stanzas["event"] = {}
                    update(stanzas["event"], kwsearch(event_keywords,linecomp,single_value=True))
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
            result = re.match('<virtualhost\s+([^>]+)', linecomp, re.IGNORECASE )
            if result:
                server_line = str(linenum)
                vhost_start = stanza_count
                
                if not server_line in stanzas:
                    stanzas[server_line] = { }
                stanzas[server_line]["virtualhost"] = result.group(1)
                if not "config_file" in stanzas[server_line]:
                    stanzas[server_line]["config_file"] = []
                # there should only be one config file, but just in case, we will append it
                if not filechain[-1] in stanzas[server_line]["config_file"]:
                    stanzas[server_line]["config_file"].append(filechain[-1])
                continue # if this is a server { start, there shouldn't be anything else on the line
            # only match these in a virtual host
            if vhost_start == stanza_count:
                keywords = vhost_keywords
                update(stanzas[server_line], kwsearch(keywords,line.strip() ) )
            # closing VirtualHost
            result = re.match('</virtualhost', linecomp, re.IGNORECASE )
            if result:
                vhost_start = -1
                continue
            # end virtual host matching
    
        # this section is so the same information shows up in nginx and apache, to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] =  []
        for i in stanzas.keys():
            if ("documentroot" in stanzas[i]) or ("servername" in stanzas[i]) or ("serveralias" in stanzas[i]) or ("virtualhost" in stanzas[i]):
                configuration["sites"].append( { } )
                if "servername" in stanzas[i]:
                    if not "domains" in configuration["sites"][-1]:
                        configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["servername"]
                if "serveralias" in stanzas[i]:
                    if not "domains" in configuration["sites"][-1]:
                        configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["serveralias"]
                if "virtualhost" in stanzas[i]:
                    if not "listening" in configuration["sites"][-1]:
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
        if not "maxprocesses" in stanzas: # there was a stanzas["config"] but that isn't what is referenced later
            mpm = self.get_mpm().lower()
            if mpm == "prefork":
                if stanzas.get("prefork",{}).get("maxclients"):
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
                    if stanzas.get("event",{}).get("serverlimit"):
                        event_limit_one = int(stanzas["event"]["serverlimit"])
                    else:
                        event_limit_one = None
                    if stanzas.get("event",{}).get("maxrequestworkers") and stanzas.get("event",{}).get("threadsperchild"):
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
                    if stanzas.get("worker",{}).get("maxclients"):
                        stanzas["maxprocesses"] = int(stanzas["worker"]["maxclients"])
            else:
                sys.stderr.write("Could not identify mpm in use.\n")
                error_collection.append("apache error: Could not identify mpm in use.\n")
                sys.exit(1)
            pass

        return stanzas

class nginxCtl(object):
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        if not "exe" in self.kwargs:
            self.kwargs["exe"] = "nginx"
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
        version = self.kwargs["exe"]+" -v 2>&1"
        p = subprocess.Popen(
            version, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
            )
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
        conf = self.kwargs["exe"]+" -V 2>&1 | grep 'configure arguments:'"
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
        return dict

    def get_conf(self):
        """
        :returns: nginx configuration path location
        """
        try:
            return self.get_conf_parameters()['--conf-path']
        except KeyError:
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

    def parse_config(self,wholeconfig):
        """
        list structure
        { line : { listen: [ ], server_name : [ ], root : path } }
        """
        stanza_chain = []
        stanza_count = 0
        server_start = -1
        #server_line = -1
        location_start = 0
        linenum = 0
        filechain = []
        stanzas = {} #AutoVivification()
        # keywords
        server_keywords = ["listen", "root", "ssl_prefer_server_ciphers", "ssl_protocols", "ssl_ciphers", "access_log", "error_log"]
        server_keywords_split = ["server_name"]
        for line in wholeconfig.splitlines():
            linenum += 1
            linecomp = line.strip().lower()
            # when we start or end a file, we inserted ## START or END so we could identify the file in the whole config
            # as they are opened, we add them to a list, and remove them as they close.
            # then we can use their name to identify where it is configured
            filechange = re.match("## START (.*)",line)
            if filechange:
                filechain.append(filechange.group(1))
            filechange = re.match("## END (.*)",line)
            if filechange:
                filechain.pop()
            # filechain[-1] for the most recent element
            # this doesn't do well if you open and close a stanza on the same line
            if len(re.findall('{',line)) > 0 and len(re.findall('}',line)) > 0:
                if not "error" in stanzas:
                    stanzas["error"] = "nginx config file: This script does not consistently support opening { and closing } stanzas on the same line.\n"
                    error_collection.append("nginx config file: This script does not consistently support opening { and closing } stanzas on the same line.\n")
                stanzas["error"] += "line %d: %s\n" % (linenum,line.strip())
                error_collection.append("line %d: %s\n" % (linenum,line.strip()))
            stanza_count+=len(re.findall('{',line))
            stanza_count-=len(re.findall('}',line))
            result = re.match("(\S+)\s*{",linecomp)
            if result:
                stanza_chain.append({ "linenum" : linenum, "title" : result.group(1) })
            if len(re.findall('}',line)) and len(stanza_chain) > 0:
                stanza_chain.pop()
    
            # start server { section
            # is this a "server {" line?
            result = re.match('^\s*server\s', linecomp, re.IGNORECASE )
            if result:
                server_start = stanza_count
                server_line = str(linenum)
                if not server_line in stanzas:
                    stanzas[server_line] = { }
                if not "config_file" in stanzas[server_line]:
                    stanzas[server_line]["config_file"] = []
                # there should only be one config file, but just in case, we will append it
                if not filechain[-1] in stanzas[server_line]["config_file"]:
                    stanzas[server_line]["config_file"].append(filechain[-1])
                #continue # if this is a server { start, there shouldn't be anything else on the line
            # are we in a server block, and not a child stanza of the server block? is so, look for keywords
            # this is so we don't print the root directive for location as an example. That might be useful, but isn't implemented at this time.
            if server_start == stanza_count:
                # we are in a server block
                #result = re.match('\s*(listen|server|root)', line.strip())
                keywords = server_keywords
                if not server_line in stanzas:
                    stanzas[server_line] = { }
                update(stanzas[server_line], kwsearch(keywords,line))
                keywords = server_keywords_split
                if not server_line in stanzas:
                    stanzas[server_line] = { }
                if not "server_name" in stanzas[server_line]:
                    stanzas[server_line]["server_name"] = []
                if kwsearch(["server_name"],line):
                    stanzas[server_line]["server_name"] += kwsearch(["server_name"],line)["server_name"][0].split()
                """
                for word in keywords:
                    result = re.match("\s*(%s)\s*(.*)" % word, line.strip("\s\t;"), re.IGNORECASE)
                    if result:
                        if not word in stanzas[server_line]:
                            stanzas[server_line][word] = []
                        stanzas[server_line][word] += [result.group(2)]
                """
            elif stanza_count < server_start:
                # if the server block is bigger than the current stanza, we have left the server stanza we were in
                # if server_start > stanza_count and server_start > 0: # The lowest stanza_count goes is 0, so it is redundant
                # we are no longer in the server { block
                server_start = -1
            # end server { section
            
            # keywords is a list of keywords to search for
            # look for keywords in the line
            # pass the keywords to the function and it will extract the keyword and value
            keywords = ["worker_processes"]
            update(stanzas, kwsearch(keywords,line))
    
        # this section is so the same information shows up in nginx and apache, to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] =  []
        
        # pressing the whole web daemon config in to a specific framework so it is easier to work with
        for i in stanzas.keys():
            if ("root" in stanzas[i]) or ("server_name" in stanzas[i]) or ("listen" in stanzas[i]):
                # "access_log", "error_log"
                configuration["sites"].append( { } )
                if "server_name" in stanzas[i]:
                    if not "domains" in configuration["sites"][-1]:
                        configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["server_name"]
                if "listen" in stanzas[i]:
                    if not "listening" in configuration["sites"][-1]:
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
            stanzas["maxprocesses"] = int(stanzas["worker_processes"][0])
    
        return stanzas

class phpfpmCtl(object):
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        if not "exe" in self.kwargs:
            self.kwargs["exe"] = "php-fpm"
    def figlet(self):
        print """
       _                  __                 
 _ __ | |__  _ __        / _|_ __  _ __ ___  
| '_ \| '_ \| '_ \ _____| |_| '_ \| '_ ` _ \ 
| |_) | | | | |_) |_____|  _| |_) | | | | | |
| .__/|_| |_| .__/      |_| | .__/|_| |_| |_|
|_|         |_|             |_|
"""

    def get_version(self):
        """
        Discovers installed nginx version
        """
        version = self.kwargs["exe"]+" -v"
        p = subprocess.Popen(
            version, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
            )
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        else:
            return(output)

    def get_conf_parameters(self):
        conf = self.kwargs["exe"]+" -V 2>&1"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        if p.returncode > 0:
            return()
        dict = {}
        compiled=0
        for i in output.splitlines():
            if i.strip()=="Server compiled with....":
                compiled=1
                continue
            if compiled == 0:
                result = re.match('\s*([^:]+):\s*(.+)', i.strip())
                if result:
                    dict[result.group(1)]=result.group(2)
            else:
                result = re.match('\s*-D\s*([^=]+)=?"?([^"\s]*)"?', i.strip() )
                if result:
                    dict[result.group(1)]=result.group(2)
        return dict

    def get_conf(self):
        """
        :returns: configuration path location
        HTTPD_ROOT/SERVER_CONFIG_FILE
        """
        phpfpm_process = daemon_exe(["php-fpm"]) # phpfpm_process["cmd"][0]
        if phpfpm_process:
            # the cmd line looks like: php-fpm: master process (/etc/php-fpm.conf)
            result = re.search('\((\S+)\)',phpfpm_process["php-fpm"]["cmd"])
            if result:
                return(result.group(1))
        sys.exit(1)

    def parse_config(self,wholeconfig):
        stanza_chain = []
        linenum = 0
        filechain = []
        stanzas = {} #AutoVivification()
        server_keywords = ["listen", "root", "ssl_prefer_server_ciphers", "ssl_protocols", "ssl_ciphers"
                           "pm", "pm.max_children", "pm.start_servers", "pm.min_spare_servers", "pm.max_spare_servers"
                           ]
        server_keywords_split = ["server_name"]
        for line in wholeconfig.splitlines():
            linenum += 1
            linecomp = line.strip().lower()
            # when we start or end a file, we inserted ## START or END so we could identify the file in the whole config
            # as they are opened, we add them to a list, and remove them as they close.
            # then we can use their name to identify where it is configured
            filechange = re.match("## START (.*)",line)
            if filechange:
                filechain.append(filechange.group(1))
                #continue
            filechange = re.match("## END (.*)",line)
            if filechange:
                filechain.pop()
                #continue
            
            # stanza change
            result = re.match('[;#]', linecomp )
            if result:
                continue
            result = re.match('\[(\S+)\]', linecomp )
            if result:
                # the previous one ends when the new one starts
                # end
                if len(stanza_chain) > 0:
                    stanza_chain.pop()
                # start
                stanza_chain.append({ "linenum" : linenum, "title" : result.group(1) })
            else:
                #match not spaces or =, then match = and spaces, then not spaces
                result = re.match('([^=\s]+)\s*=\s*(\S+)', linecomp )
                if result:
                    key = result.group(1)
                    value = result.group(2)
                    if not stanza_chain[-1]["title"] in stanzas:
                        stanzas[stanza_chain[-1]["title"]] = {}
                    stanzas[stanza_chain[-1]["title"]][key] = value
        stanzas["maxprocesses"] = 0
        for one in stanzas:
            if type(stanzas[one]) is dict:
                if stanzas.get(one,{}).get("pm.max_children"):
                    stanzas["maxprocesses"] += int(stanzas[one]["pm.max_children"])
        return(stanzas)

class MagentoCtl(object):
    def figlet(self):
        print """
 __  __                        _        
|  \/  | __ _  __ _  ___ _ __ | |_ ___  
| |\/| |/ _` |/ _` |/ _ \ '_ \| __/ _ \ 
| |  | | (_| | (_| |  __/ | | | || (_) |
|_|  |_|\__,_|\__, |\___|_| |_|\__\___/ 
              |___/
"""

    def parse_version(self, mage_php_file):
        mage = {}
        file_handle = open(mage_php_file, 'r')
        for line in file_handle:
            result = re.match("static\s+private\s+\$_currentEdition\s*=\s*self::([^\s;]+);", line.strip(), re.IGNORECASE )
            if result:
                mage["edition"] = result.group(1)
            if "public static function getVersionInfo()" in line:
                line = file_handle.next() # {
                line = file_handle.next() # return array(
                while not ");" in line:
                    line = file_handle.next()
                    result = re.match("'([^']+)'\s*=>\s*'([^']*)'", line.strip())
                    if result:
                        mage[result.group(1)] = result.group(2)
                #break
        file_handle.close()
        # join them with periods, unless they are empty, then omit them
        mage["version"] = ".".join(filter(None,[mage["major"],mage["minor"],mage["revision"],mage["patch"],mage["stability"],mage["number"]]))

        # This is to address 1.10.1.1 EE that has no $_currentEdition defined
        if not "edition" in mage:
            mage["edition"] = ""
        return(mage)
    
    def localxml(self, local_xml_file):
        pass
    def find_mage_php(self,doc_roots):
        return_dict = {}
        for doc_root_path in doc_roots:
            # with nginx and apache, we have docroot for web paths
            # we need to search those for Mage.php and local.xml
            #magento = MagentoCtl()
            
            #search_path = one # docroot
            mage_php_matches = []
            for root, dirnames, filenames in os.walk(doc_root_path):
                for filename in fnmatch.filter(filenames, 'Mage.php'):
                    mage_php_matches.append(os.path.join(root, filename))
        
            if len(mage_php_matches) > 1:
                sys.stderr.write("There are multiple Mage.php files in the Document Root %s. Choosing the shortest path.\n" % doc_root_path)
                error_collection.append("Magento error: There are multiple Mage.php files in the Document Root %s. Choosing the shortest path.\n" % doc_root_path)
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
                        
            if mage_php_matches:
                return_dict[doc_root_path] = mage_php_matches[0]
        return(return_dict)
        # if return_dict:
        #     print "returning %r" % return_dict
        #     return(return_dict)
        # else:
        #     sys.exit(1)

    def mage_file_info(self,mage_files):
        return_dict = {}
        for doc_root_path, mage_php_match in mage_files.iteritems():
            return_dict[doc_root_path] = {}
            mage = self.parse_version(mage_php_match)
            head,tail = os.path.split(os.path.dirname(mage_php_match))
            return_dict[doc_root_path]["Mage.php"] = mage_php_match
            return_dict[doc_root_path]["magento_path"] = head
            return_dict[doc_root_path]["local_xml"] = { }
            return_dict[doc_root_path]["local_xml"]["filename"] = os.path.join(head, "app", "etc", "local.xml")
            return_dict[doc_root_path]["magento_version"] = "%s" % mage["version"]
            if mage["edition"]:
                return_dict[doc_root_path]["magento_version"] += " %s" % mage["edition"]
            return_dict[doc_root_path]["mage_version"] = mage
        return(return_dict)
    
    def open_local_xml(self, doc_root):
        """
        provide the filename (absolute or relative) of local.xml
        
        returns: dict with db and cache information
        """
        filename = os.path.join(doc_root,"app","etc","local.xml")
        try:
            #if True:
            tree = ET.ElementTree(file=filename)
        except IOError:
            sys.stderr.write("Could not open file %s\n" % filename)
            return()
            #sys.exit(1)

        #tree = ET.ElementTree(file='local.xml')
        #tree = ET.ElementTree(file='local-memcache.xml')
        local_xml = {}
        
        section = "db"
        xml_parent_path = 'global/resources'
        xml_config_node = 'db/table_prefix'
        xml_config_section = 'default_setup/connection'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
        
        section = "session_cache"
        xml_parent_path = 'global'
        xml_config_node = 'session_save'
        xml_config_section = 'redis_session'
        xml_config_single = 'session_save_path'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section, xml_config_single = 'session_save_path'))
        # test for session cache redis
        resources = tree.find("global/redis_session")
        if resources is not None:
            local_xml[section]["engine"] = "redis"
            redis_module_xml = os.path.join(doc_root,"app","etc","modules","Cm_RedisSession.xml")
            #print "908 redis module xml: %s" % redis_module_xml
            # app/etc/modules/Cm_RedisSession.xml
            # xml config/modules/Cm_RedisSession/active
            try:
                redis_tree = ET.ElementTree(file=redis_module_xml)
                Cm_RedisSession = redis_tree.find("modules/Cm_RedisSession/active")
                if Cm_RedisSession is not None:
                    #print "opened Cm_RedisSession.xml"
                    if Cm_RedisSession.text is not None:
                        #print "and found %s" % Cm_RedisSession.text
                        local_xml[section]["Cm_RedisSession.xml active"] = Cm_RedisSession.text
            except IOError:
                error_collection.append("The file %s could not be opened." % redis_module_xml)
                local_xml[section]["Cm_RedisSession.xml active"] = "File not found"
        elif local_xml.get(section,{}).get(xml_config_node,"").lower() == "memcache":
            local_xml[section]["engine"] = "memcache"
        else:
            local_xml[section]["engine"] = "unknown"
        
        section = "object_cache"
        xml_parent_path = 'global/cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
        if local_xml.get(section,{}).get(xml_config_node,"").lower() == "mage_cache_backend_redis":
            local_xml[section]["engine"] = "redis" # Magento's redis module
        elif local_xml.get(section,{}).get(xml_config_node,"").lower() == "cm_cache_backend_redis":
            local_xml[section]["engine"] = "redis" # Colin M's redis module
        elif local_xml.get(section,{}).get(xml_config_node,"").lower() == "memcached":
            xml_parent_path = 'global/cache'
            xml_config_node = 'backend'
            xml_config_section = 'memcached/servers/server'
            update(local_xml, self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
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
        
        section = "full_page_cache"
        xml_parent_path = 'global/full_page_cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        xml_config_single = 'slow_backend'
        update(local_xml, self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section, xml_config_single = 'slow_backend'))
        if local_xml.get(section,{}).get(xml_config_node,"").lower() == "mage_cache_backend_redis":
            local_xml[section]["engine"] = "redis" # Magento's redis module
        elif local_xml.get(section,{}).get(xml_config_node,"").lower() == "cm_cache_backend_redis":
            local_xml[section]["engine"] = "redis" # Colin M's redis module
        elif local_xml.get(section,{}).get(xml_config_node,"").lower() == "memcached":
            local_xml[section]["engine"] = "memcache" # Colin M's redis module
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
        #section = "full_page_cache"
        #xml_parent_path = 'global/full_page_cache'
        #xml_config_node = 'backend'
        #xml_config_section = 'backend_options'
        if "xml_config_single" in kwargs:
            xml_config_single = kwargs["xml_config_single"]
        else:
            xml_config_single = ""
            
        if not section in local_xml:
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
            # else:
            #     sys.stderr.write("Did not find the XML config %s in %s\n" % (xml_config_section,section))
                    
            if xml_config_single:
                if resources.find(xml_config_single) is not None:
                    i = resources.find(xml_config_single)
                    local_xml[section][i.tag] = i.text
                # else:
                #     sys.stderr.write("Did not find the XML config single %s in %s\n" % (xml_config_single,section))


        # configuration
        return local_xml

    def db_cache_table(self, doc_root, value):
        #globalconfig["magento"]["doc_root"][doc_root]["cache"]["cache_option_table"]
        #doc_roots = globalconfig["magento"]["doc_root"]
        return_config = { }
        var_table_prefix = value.get("local_xml",{}).get("db",{}).get("db/table_prefix","")
        var_dbname = value.get("local_xml",{}).get("db",{}).get("dbname","")
        var_host = value.get("local_xml",{}).get("db",{}).get("host","")
        var_username = value.get("local_xml",{}).get("db",{}).get("username","")
        var_password = value.get("local_xml",{}).get("db",{}).get("password","")
        if (var_dbname and var_host and var_username and var_password ):
            sqlquery = "select * FROM %s.%score_cache_option;" % (var_dbname,var_table_prefix)
            conf = "mysql --table --user='%s' --password='%s' --host='%s' --execute='%s' 2>&1 " % (
                var_username,
                var_password,
                var_host,
                sqlquery
                )
            sys.stderr.write("Querying MySQL...\n") #fixme --verbose?
            p = subprocess.Popen(
                conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, err = p.communicate()
            if p.returncode > 0 or not output:
                #return()
                sys.stderr.write("MySQL cache table query failed\n")
                error_collection.append("MySQL cache table query failed: %s\n" % conf)
                if err:
                    sys.stderr.write("err %s\n" % err)
                    error_collection.append("err %s\n" % err)
                sys.stderr.write("command: %s\n" % conf)
                error_collection.append("command: %s\n" % conf)
            else:
                # print "Mysql cache table:"
                # print "%s" % output
                #return_config = { "cache" : { "cache_option_table" : "" } }
                #globalconfig["magento"]["doc_root"][doc_root]    ["cache"]["cache_option_table"] = output
                if not return_config.get("cache",{}).get("cache_option_table"):
                    return_config = {"cache" : { "cache_option_table" : "" } } 
                return_config["cache"]["cache_option_table"] = output
        # else:
            # print "Skipping database because there isn't enough login information"
            # print " Table prefix: %s" % var_table_prefix
            # print " dbname: %s" % var_dbname
            # print " host: %s" % var_host
            # print " username: %s" % var_username
            # if var_password:
            #     print " password present but not displayed"
            # print " password: %s" % var_password
        #print
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
            sys.stderr.write("ERROR, one of these is none, ip: %s port: %s\n" % (ip,port))
            sys.exit(1)
        port = int(port)
        if kwargs.get("password") is not None:
            # print "1097 redis password found" #rmme
            reply = socket_client(ip,port,["AUTH %s\n" % kwargs["password"], "INFO\n"])
        else:
            # print "1100 redis password skipped" #rmme
            reply = socket_client(ip,port,"INFO\n")
        return(reply)
    def parse_status(self, reply):
        return_dict = {}
        section = ""
        for i in reply.splitlines():
            if len(i.strip()) == 0:
                continue
            if i.lstrip()[0] == "#":   # IndexError: string index out of range
                # new section
                section = i.lstrip(' #').rstrip()
                if not section in return_dict:
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
                return_dict[section][key] = value
        return(return_dict)
    def get_all_statuses(self, instances, **kwargs):
        return_dict = {}
        # print "1127 get_all_statuses" #rmme
        # pp.pprint(instances) #rmme
        for i in instances:
            host = instances[i]["host"]
            port = instances[i]["port"]
            password = instances[i]["password"]
            # [host, port] = i.split(":")
            if not return_dict.get(i):
                return_dict[i] = {}
            # print "1072 %r" % (i)
            # need to check for a password
            # password will be None if there wasn't one in the local.xml
            # I could just pass the None value through without checking because it is check for None in get_status
            if password is not None:
                reply = self.get_status(host, port, password = password)
            else:
                reply = self.get_status(host, port)
            return_dict[i] = self.parse_status(reply)
        return(return_dict)
    def instances(self, doc_roots):
        """
        With a list of doc_roots, examine the local xml we already parsed
        Make a list of redis instances, return the IP or hostname, port and password (password as applicable)
        
        Returns a dict of "host:port" : {"host": "", "port": "", "password":""}
        Value is None if it is undefined
        
        Previously, a list of "host:port" was returned.
        You could iterate for i in instances().
        The return was changed to a dict, and the key is "host:port" so for i in instances() will still work,
        With the added benefit that you can now get to the values directly.
        """
        redis_instances = set()
        redis_dict = {} # "host:port" : {host:"",port:"",password:""}
        for doc_root in doc_roots:
            # SESSION
            # for this doc_root, if the session cache is memcache, get the ip and port, and add it to the set
            # redis
            if globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{}):
                local_xml = globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{})
            if local_xml.get("session_cache",{}).get("engine") == "redis":
                stanza = "%s:%s" % (
                    local_xml.get("session_cache",{}).get("host"),
                    local_xml.get("session_cache",{}).get("port")
                )
                redis_instances.add(stanza)
                redis_dict[stanza] = {}
                #if local_xml.get("session_cache",{}).get("host"):
                redis_dict[stanza]["host"] = local_xml.get("session_cache",{}).get("host")
                #if local_xml.get("session_cache",{}).get("port"):
                redis_dict[stanza]["port"] = local_xml.get("session_cache",{}).get("port")
                redis_dict[stanza]["password"] = local_xml.get("session_cache",{}).get("password")
                #print "1098 redis_dict %r" % redis_dict

            # OBJECT
            # for this doc_root, if the object cache is memcache, get the ip and port, and add it to the set
            # redis
            if local_xml.get("object_cache",{}).get("engine") == "redis":
                stanza = "%s:%s" % (
                    local_xml.get("object_cache",{}).get("server"),
                    local_xml.get("object_cache",{}).get("port")
                )
                redis_instances.add(stanza)
                redis_dict[stanza] = {}
                redis_dict[stanza]["host"] = local_xml.get("session_cache",{}).get("host")
                redis_dict[stanza]["port"] = local_xml.get("session_cache",{}).get("port")
                redis_dict[stanza]["password"] = local_xml.get("session_cache",{}).get("password")
                #print "1115 redis_dict %r" % redis_dict

            # FULL PAGE CACHE
            # redis
            if local_xml.get("full_page_cache",{}).get("engine") == "redis":
                stanza = "%s:%s" % (
                    local_xml.get("full_page_cache",{}).get("server"),
                    local_xml.get("full_page_cache",{}).get("port")
                )
                redis_instances.add(stanza)
                redis_dict[stanza] = {}
                #if local_xml.get("session_cache",{}).get("host"):
                redis_dict[stanza]["host"] = local_xml.get("session_cache",{}).get("host")
                #if local_xml.get("session_cache",{}).get("port"):
                redis_dict[stanza]["port"] = local_xml.get("session_cache",{}).get("port")
                redis_dict[stanza]["password"] = local_xml.get("session_cache",{}).get("password")
                #print "1131 redis_dict %r" % redis_dict
            # if redis_dict:
            #     print "redis_dict:"
            #     pp.pprint(redis_dict)
        #return(list(redis_instances))
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
        reply = socket_client(ip,port,"stats\n")
        return(reply)
    def parse_status(self, reply):
        return_dict = {}
        section = ""
        for i in reply.splitlines():
            if len(i.strip()) == 0:
                continue
            try:
                [STAT, key, value] = i.split(' ', 3)
            except ValueError:
                STAT = None
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
            print "1144 %r" % (instance)
            # need to check for a password
            reply = self.get_status(ip, port)
            return_dict[instance] = self.parse_status(reply)
        return(return_dict)
    def instances(self, doc_roots):
        memcache_instances = set()
        for doc_root in doc_roots:
            # SESSION
            # for this doc_root, if the session cache is memcache, get the ip and port, and add it to the set
            # memcache
            if globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{}).get("session_cache",{}).get("engine") == "memcache":
                result = re.match('tcp://([^:]+):(\d+)',
                    globalconfig["magento"]["doc_root"][doc_root]["local_xml"].get("session_cache",{}).get("session_save_path")
                    )
                if result:
                    ip = result.group(1)
                    port = result.group(2)
                    stanza = "%s:%s" % (ip,port)
                    memcache_instances.add(stanza)
            # OBJECT
            # for this doc_root, if the object cache is memcache, get the ip and port, and add it to the set
            # memcache
            if globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{}).get("object_cache",{}).get("engine") == "memcache":
                stanza = "%s:%s" % (
                    globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{}).get("object_cache",{}).get("host"),
                    globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{}).get("object_cache",{}).get("port")
                )
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
def socket_client(host, port, string, **kwargs):
    if "TIMEOUT" in kwargs:
        timeout = int(kwargs["TIMEOUT"])
    else:
        timeout = 5
    if isinstance(string, basestring):
        strings = [ string ]
    else:
        strings = string
    #ip, port = '172.24.16.68', 6386
    # SOCK_STREAM == a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    #sock.setdefaulttimeout(timeout)
    #sock.setblocking(0)  # optional non-blocking
    try:
        sock.connect((host, int(port)))
        for string in strings:
            sock.send(string)
            reply = sock.recv(16384)  # limit reply to 16K
            print "1352 reply %s" % reply
        sock.close()
    except socket.error:
        sys.exit(1)
        return(0)
    return reply

def daemon_exe(match_exe):
    """
    var_filter = "text to search with"
    using this as the filter will find an executable by name whether it was call by absolute path or bare
    "^(\S*/bash|bash)"
    """
    daemons = {}
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    #pp.pprint(pids)

    for pid in pids:
        psexe = ""
        ppid = ""
        pscmd = ""
        pserror = ""
        try:
            ppid = open(os.path.join('/proc', pid, 'stat'), 'rb').read().split()[3]
            pscmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read().replace("\000"," ").rstrip()
            psexe = os.path.realpath(os.path.join('/proc', pid, 'exe'))
        except (IOError,OSError): # proc has already terminated, you may not be root
            continue

        # if the exe has been deleted (i.e. through an rpm update), the exe will be "/usr/sbin/nginx (deleted)"
        if psexe:
            if re.search('\(deleted\)', psexe):
                # if the exe has been deleted (i.e. through an rpm update), the exe will be "/usr/sbin/nginx (deleted)"
                pserror = psexe
                result = re.match('([^\(]+)', psexe)
                psexe = result.group(1).rstrip()
                pass
            if os.path.basename(psexe) in match_exe:
                #if os.path.basename(psexe) == daemon_name:
                if ppid == "1" or not os.path.basename(psexe) in daemons:
                    daemons[os.path.basename(psexe)] = { "exe" : "", "cmd" : "", "basename" : "" }
                    daemons[os.path.basename(psexe)]["exe"] = psexe
                    daemons[os.path.basename(psexe)]["cmd"] = pscmd
                    daemons[os.path.basename(psexe)]["basename"] = os.path.basename(psexe)
                    if pserror:
                        daemons[os.path.basename(psexe)]["error"] = "Process %s, %s is in (deleted) status. It may not exist, or may have been updated." % (pid,pserror)
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
        wholeconfig = importfile(conffile,'\s*include\s+(\S+)')
    httpd
        wholeconfig = importfile(conffile,'\s*include\s+(\S+)', base_path="/etc/httpd")
    """
    # make the base_path incoming keyword a little more fault tolerant by removing the trailing slash
    if "base_path" in kwargs:
        base_path = kwargs["base_path"].rstrip("/")
    else:
        base_path = ""
    if "recurse_count" in kwargs:
        kwargs["recurse_count"] += 1
        # kwargs["recurse_count"] += 1 shouldn't be adding this twice
    else:
        kwargs["recurse_count"] = 0
    if kwargs["recurse_count"] > 10:
        #arbitrary number
        sys.stderr.write("Too many recursions while importing %s, the config is probably a loop.\n" % filename)
        error_collection.append("Too many recursions while importing %s, the config is probably a loop.\n" % filename)
        sys.exit(1)
    def full_file_path(right_file, base_path):
        # If the right side of the full name doesn't have a leading slash, it is a relative path.
        #     Add the base_path to the left and return the value
        # else just return the name
        if right_file[0] not in "/":
            #return(base_path+"/"+right_file)
            return(os.path.join(base_path, right_file))
        else:
            return(right_file) # this is the fix!
    #files = glob.iglob( full_file_path(filename, base_path) ) # either an absolute path to a file, or absolute path to a glob
    files = glob.glob( full_file_path(filename, base_path) ) # either an absolute path to a file, or absolute path to a glob
    combined = ""

    for onefile in files:
        # for each file in the glob (may be just one file), open it
        # try:
        if True:
            onefile_handle = open(onefile, 'r')
            # onefile should always be a file
            if os.path.isfile(onefile):
                combined += "## START "+onefile+"\n"
        # except:
        #     return()

        # go through the file, line by line
        # if it has an include, go follow it
        for line in onefile_handle:
            result = re.match(keyword_regex, line.strip(), re.IGNORECASE )
            #result = re.match('(include.*)', line.strip(), re.I | re.U )
            # if it is an include, remark out the line,
            # figure out the full filename
            # and import it inline
            if result:
                combined += "#"+line+"\n"
                nestedfile = full_file_path(result.group(1), base_path)
                combined += importfile(nestedfile, keyword_regex, **kwargs)
            else:
                combined += line
        # END of the file import, if it was a file and not a glob, make the ending. onefile should always be a file
        if os.path.isfile(onefile):
            combined += "## END "+onefile+"\n"
        onefile_handle.close()
    return combined

def kwsearch(keywords,line, **kwargs):
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
        #result = re.search("\s*(%s)\s*(.*)" % word, line.strip(), re.IGNORECASE)
        #result = re.search("\s*(%s)\s*(.*)" % '|'.join(map(str,keywords)), line.strip(), re.IGNORECASE) # this way, without the for loop took 10-12 times as long to run
        if result:
            if not "single_value" in kwargs:
                if not result.group(1).lower() in stanza:
                    stanza[result.group(1).lower()] = []
                if not result.group(2).strip('\'"') in stanza[result.group(1).lower()]:
                    if not "split_list" in kwargs:
                        stanza[result.group(1).lower()] += [result.group(2).strip(';"\'')]
                    else:
                        stanza[result.group(1).lower()] += [result.group(2).strip(';"\'').split()]
            else:
                stanza[result.group(1)] = result.group(2).strip('"\'')
    return(stanza) #once we have a match, move on

def memory_estimate(process_name, **kwargs):
    """
    line_count 16
    biggest 17036
    free_mem 1092636
    line_sum 61348
    """
    status = { "line_sum":0, "line_count":0, "biggest":0, "free_mem":0 }

    #freeMem=`free|egrep '^Mem:'|awk '{print $4}'`
    conf = "free"
    p = subprocess.Popen(
        conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, err = p.communicate()
    if not output:
        raise NameError("Fail: %s" % err)
    for line in output.splitlines():
        result = re.match('(Mem:)\s+(\S+)\s+(\S+)\s+(\S+)', line)
        if result:
            status["free_mem"] = int(result.group(4))

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
            if int(result.group(6)) > status["biggest"]:
                status["biggest"] = int(result.group(6))
    return(status)

def memory_print(result, proc_name, proc_max):
    print "%d %s processes are currently using %d KB of memory, and there is %d KB of free memory." % (result["line_count"], proc_name, result["line_sum"], result["free_mem"])
    print "Average memory per process: %d KB will use %d KB if max processes %d is reached." % (result["line_sum"]/result["line_count"], int(result["line_sum"] / result["line_count"] * proc_max), proc_max)
    print "Largest process: %d KB will use %d KB if max processes is reached.\n" % (result["biggest"], result["biggest"]*proc_max)
    print "What should I set max processes to?"
    print "The safe value would be to use the largest process, and commit 80%% of memory: %d" % int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
    print
    print "Current maximum processes: %d" % proc_max
    print "avg 100% danger   avg 80% warning   lrg 100% cautious   lrg 80% safe"
    print "     %3d                %3d                %3d              %3d" % (
        int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) )),
        int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) ) * .8),
        int( (result["line_sum"]+result["free_mem"]) / result["biggest"]),
        int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
        )

def print_sites(localconfig):
    for one in sorted(localconfig):
        if "domains" in one:
            print "Domains: %s" % "  ".join(one["domains"])
        if "listening" in one:
            print "listening: %r" % ", ".join(one["listening"])
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
    #for k, v in u.iteritems():
    for k in u:
        # if isinstance(v, collections.Mapping):
        if isinstance(u[k], dict):
            r = update(d.get(k, {}), u[k])
            d[k] = r
        else:
            d[k] = u[k]
    return d

pp = pprint.PrettyPrinter(indent=4)

# The argparse module is not installed on many systems. This way, it will work regardless
if ARGPARSE:
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "-j", "--jsonfile", help="Name of a config dump json file. Skips detection and uses file values.",
                        )
    parser.add_argument("-s", "--silent",
                        help="No output, not even stderr.",
                        action="store_true")
    parser.add_argument("-v", "--verbose",
                        help="Additional output, mostly to stderr.",
                        action="store_true")
    parser.add_argument("-F", "--nofiglet", help="Omits big text (figlet) banners. Banners do not require figlet to be installed.",
                        action="store_true")
    # parser.add_argument("--plaintext", help="ANSI control characters are omitted for colors and screen clear/home.",
    #                     action="store_true")
    parser.add_argument("-f", "--force", help="If config_dump.json already exists, overwrite it. Default: do not overwrite.",
                        action="store_true")
    parser.add_argument("-o", "--output", help="Name of json file to place saved config in. Default: ./config_dump.json",
                        default="./config_dump.json")
    parser.add_argument("--printwholeconfig", help="Print the concat (whole) config of a daemon(s). Requires additional daemon switches.",
                        action="store_true")
    parser.add_argument("--apache", help="Daemon specific switch for other options (printwholeconfig)",
                        action="store_true")
    parser.add_argument("--nginx", help="Daemon specific switch for other options (printwholeconfig)",
                        action="store_true")
    parser.add_argument("--phpfpm", help="Daemon specific switch for other options (printwholeconfig)",
                        action="store_true")
    parser.add_argument("--printglobalconfig", help="Pretty print the globalconfig dict",
                        action="store_true")
    parser.add_argument("--printjson", help="Pretty print the globalconfig json",
                        action="store_true")    
    """
    parser.add_argument("--nopassword", help="Omits passwords from screen output and json capture.",
                        action="store_true")
    """

    args = parser.parse_args()
    
    # if (args.silent or args.batch) and not args.runtime:
    #     args.runtime = 30
    #     pass
    # if args.batch:
    #     args.plaintext = True
    # if args.batch:
    #     pass
else:
    args = argsAlt()
    args.jsonfile = None
    args.silent = None
    args.verbose = None
    args.nofiglet = None
    args.force = None
    args.printwholeconfig = None
    args.printglobalconfig = None
    args.apache = None
    args.nginx = None
    args.phpfpm = None
    args.output = "./config_dump.json"
    args.printjson = None
    # args.nopassword = None
    """
    defaults:
        save a config_dump
        do not show verbose messages
        show figlet banners
        do not overwrite config_dump.json
        json filename, default config_dump.json
    """

if args.jsonfile and JSON == True:
    if os.path.isfile(args.jsonfile):
        # try:
        if True:
            # with open(args.jsonfile,'r') as f:
            #     globalconfig=json.load(f)
            f = open(args.jsonfile,'r')
            globalconfig=json.load(f)
        # except:
        #     sys.stderr.write("The file %s exists, but failed to import.\n" % args.jsonfile)
        #     sys.exit(1)
    else:
        sys.stderr.write("The file %s does not exist.\n" % args.jsonfile)
        error_collection.append("The file %s does not exist.\n" % args.jsonfile)
        sys.exit(1)

"""
need to check directory permissions
[root@localhost vhosts]# ll
total 4
drwxrwxr-x 3 user user 4096 Sep 15 17:11 example.com
"""

"""
for one in daemons:
    print "%s: %r\n" % (one,daemons[one])
"""
#pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(daemons)
apache = apacheCtl()
nginx = nginxCtl()
phpfpm = phpfpmCtl()
magento = MagentoCtl()
redis = RedisCtl()
memcache = MemcacheCtl()
if not args.jsonfile:
    # these are the daemon executable names we are looking for
    daemons = daemon_exe(["httpd", "apache2", "nginx", "bash", "httpd.event", "httpd.worker", "php-fpm", "mysql", "mysqld"])
    for i in daemons:
        if daemons.get(i,{}).get("error"):
            sys.stderr.write(daemons[i]["error"] + "\n")
            error_collection.append(daemons[i]["error"] + "\n")
    localfqdn = socket.getfqdn()
    globalconfig = { "version" : STACK_STATUS_VERSION, "fqdn": localfqdn }
    globalconfig["daemons"] = daemons
    """
     ____    _  _____  _       ____    _  _____ _   _ _____ ____  
    |  _ \  / \|_   _|/ \     / ___|  / \|_   _| | | | ____|  _ \ 
    | | | |/ _ \ | | / _ \   | |  _  / _ \ | | | |_| |  _| | |_) |
    | |_| / ___ \| |/ ___ \  | |_| |/ ___ \| | |  _  | |___|  _ < 
    |____/_/   \_\_/_/   \_\  \____/_/   \_\_| |_| |_|_____|_| \_\                                                           
    """
    class DATA_GATHER(object):
        pass    
    
    # using this as a bookmark in the IDE
    def APACHE_DATA_GATHER():
        pass
    ################################################
    # APACHE
    ################################################
    apache_exe = "" # to fix not defined
    # what if they have multiple apache daemons on different MPMs?
    if "apache2" in daemons:
        apache_basename = daemons["apache2"]["basename"]
        apache_exe = daemons["apache2"]["exe"]
        apache = apacheCtl(exe = daemons["apache2"]["exe"])
    elif "httpd" in daemons:
        apache_basename = daemons["httpd"]["basename"]
        apache_exe = daemons["httpd"]["exe"]
        apache = apacheCtl(exe = daemons["httpd"]["exe"])
    elif "httpd.event" in daemons:
        apache_basename = daemons["httpd.event"]["basename"]
        apache_exe = daemons["httpd.event"]["exe"]
        apache = apacheCtl(exe = daemons["httpd.event"]["exe"])
    elif "httpd.worker" in daemons:
        apache_basename = daemons["httpd.worker"]["basename"]
        apache_exe = daemons["httpd.worker"]["exe"]
        apache = apacheCtl(exe = daemons["httpd.worker"]["exe"])
    else:
        sys.stderr.write("Apache is not running\n")
        error_collection.append("Apache is not running\n")
    
    if apache_exe:
        # try:
        if True:
            apache_conf_file = apache.get_conf()
            apache_root_path = apache.get_root()
            apache_mpm = apache.get_mpm()
        # except:
        #     sys.stderr.write("There was an error getting the apache daemon configuration\n")
        #     apache_conf_file = ""
        #     apache_root_path = ""
        # #    apache_root_path = "/home/charles/Documents/Rackspace/ecommstatustuning/etc/httpd"
        # #    apache_conf_file = "conf/httpd.conf"
        if apache_conf_file and apache_root_path:
            sys.stderr.write("Using config %s\n" % apache_conf_file)
            error_collection.append("Using config %s\n" % apache_conf_file)
            # (?:OPTIONAL?)?  the word OPTIONAL may or may not be there as a whole word,
            # and is a non-capturing group by virtue of the (?:)
            wholeconfig = importfile(apache_conf_file, '\s*include(?:optional?)?\s+(\S+)', base_path = apache_root_path)
            if args.printwholeconfig and args.apache:
                print(wholeconfig)
            apache_config = apache.parse_config(wholeconfig)
    
            if not "apache" in globalconfig:
                globalconfig["apache"] = {}
            globalconfig["apache"] = apache_config
            globalconfig["apache"]["version"] = apache.get_version()
            """
            globalconfig[apache][sites]: [
                {
                'domains': ['wilshirewigs.com', 'www.wilshirewigs.com new.wilshirewigs.com'],
                'config_file': '/etc/httpd/conf.d/ssl.conf',
                'doc_root': '/var/www/html',
                'listening': ['192.168.100.248:443']
                }, {
                'domains': ['wilshirewigs.com', 'www.wilshirewigs.com new.wilshirewigs.com'],
                'config_file': '/etc/httpd/conf/httpd.conf',
                'doc_root': '/var/www/html',
                'listening': ['*:80']
                }, {
                'config_file': '/etc/httpd/conf.d/ssl.conf',
                'listening': ['_default_:443']
                }, {
                'config_file': '/etc/httpd/conf/httpd.conf',
                'listening': ['_default_:80']
                }, {
                'doc_root': '/var/www/html'
                }]
            """
            
            daemon_config = apache.get_conf_parameters()
            if daemon_config:
                if not "daemon" in globalconfig["apache"]:
                    globalconfig["apache"]["daemon"] = daemon_config
                globalconfig["apache"]["basename"] = apache_basename
                globalconfig["apache"]["exe"] = daemons[apache_basename]["exe"]
                globalconfig["apache"]["cmd"] = daemons[apache_basename]["cmd"]
    
    # using this as a bookmark in the IDE
    def NGINX_DATA_GATHER():
        pass
    ################################################
    # NGINX
    ################################################
    if not "nginx" in daemons:
        sys.stderr.write("nginx is not running\n")
        error_collection.append("nginx is not running\n")
    else:
        nginx = nginxCtl(exe = daemons["nginx"]["exe"])
        # try:
        if True:
            nginx_conf_file = nginx.get_conf()
        # except:
        #     sys.stderr.write("There was an error getting the nginx daemon configuration\n")
        #     #nginx_conf_file = "/home/charles/Documents/Rackspace/ecommstatustuning/etc/nginx/nginx.conf"
        #     nginx_conf_file = ""
        if nginx_conf_file:
            sys.stderr.write("Using config %s\n" % nginx_conf_file)
            error_collection.append("Using config %s\n" % nginx_conf_file)

            # configuration fetch and parse
            wholeconfig = importfile(nginx_conf_file, '\s*include\s+(\S+);')
            if args.printwholeconfig and args.nginx:
                print(wholeconfig)
            nginx_config = nginx.parse_config(wholeconfig)
            
            if not "nginx" in globalconfig:
                globalconfig["nginx"] = {}
            globalconfig["nginx"] = nginx_config
            globalconfig["nginx"]["version"] = nginx.get_version()
            """
            {
            'domains': ['www.domain.com'],
            'config_file': '/etc/nginx/conf.d/production.domain.com.conf',
            'doc_root': '/var/www/vhosts/production.domain.com/webroot',
            'listening': ['443 default ssl']
            }
    
            """
            
            
            daemon_config = nginx.get_conf_parameters()
            if daemon_config:
                if not "daemon" in globalconfig["nginx"]:
                    globalconfig["nginx"]["daemon"] = daemon_config
                globalconfig["nginx"]["basename"] = "nginx"
                globalconfig["nginx"]["exe"] = daemons["nginx"]["exe"]
                globalconfig["nginx"]["cmd"] = daemons["nginx"]["cmd"]
    
    # using this as a bookmark in the IDE
    def PHP_FPM_DATA_GATHER():
        pass
    ################################################
    # PHP-FPM
    ################################################
    #phpfpm = phpfpmCtl(exe = daemons["php-fpm"]["exe"])
    if not "php-fpm" in daemons:
        sys.stderr.write("php-fpm is not running\n")
        error_collection.append("php-fpm is not running\n")
    else:
        phpfpm = phpfpmCtl(exe = daemons["php-fpm"]["exe"])
        # try:
        if True:
            phpfpm_conf_file = phpfpm.get_conf()
        # except:
        #     sys.stderr.write("There was an error getting the php-fpm daemon configuration\n")
        #     phpfpm_conf_file = ""
        if phpfpm_conf_file:
            wholeconfig = importfile(phpfpm_conf_file, '\s*include[\s=]+(\S+)')
            if args.printwholeconfig and args.phpfpm:
                print(wholeconfig)

            phpfpm_config = phpfpm.parse_config(wholeconfig)
            
            if not "php-fpm" in globalconfig:
                globalconfig["php-fpm"] = {}
            globalconfig["php-fpm"] = phpfpm_config
            globalconfig["php-fpm"]["version"] = phpfpm.get_version()
            globalconfig["php-fpm"]["basename"] = "php-fpm"
            globalconfig["php-fpm"]["exe"] = daemons["php-fpm"]["exe"]
            globalconfig["php-fpm"]["cmd"] = daemons["php-fpm"]["cmd"]
    
    def MAGENTO_DATA_GATHER():
        pass
    ################################################
    # Magento
    ################################################
    # get a list of unique document roots
    doc_roots = set()
    if globalconfig.get("apache",{}).get("sites"):
        for one in globalconfig["apache"]["sites"]:
            if "doc_root" in one:
                doc_roots.add(one["doc_root"])
    if globalconfig.get("nginx",{}).get("sites"):
        for one in globalconfig["nginx"]["sites"]:
            if "doc_root" in one:
                doc_roots.add(one["doc_root"])
    #if not "doc_roots" in globalconfig:
    #    globalconfig["doc_roots"] = set()
    globalconfig["doc_roots"] = list(doc_roots)
    
    # magento = MagentoCtl()
    if not "magento" in globalconfig:
        globalconfig["magento"] = {}
    # find mage.php files in document roots
    # try:
    if True:
        mage_files = magento.find_mage_php(globalconfig["doc_roots"])
    # except:
    #     sys.stderr.write("No Magento found in the web document roots\n")
    # get Magento information from those Mage.php
    
    mage_file_info = magento.mage_file_info(mage_files)
    globalconfig["magento"]["doc_root"] = mage_file_info
    
    
    # try:
    if True:
        # print "1265"
        # print type(magento.mage_file_info(mage_files))
        mage_file_info = magento.mage_file_info(mage_files)
        globalconfig["magento"]["doc_root"] = mage_file_info
    # except:
        # sys.stderr.write("Failed to get magento information\n")
    
    for doc_root in globalconfig["magento"]["doc_root"]:
        if not doc_root in globalconfig["magento"]["doc_root"]:
            globalconfig["magento"]["doc_root"][doc_root] = {}
        # else:
        #     print 'DEFINED: %s in globalconfig["magento"]["doc_root"]' % doc_root
        #     print type(globalconfig["magento"]["doc_root"][doc_root])
        local_xml = os.path.join(doc_root,"app","etc","local.xml")
        if not "local_xml" in globalconfig["magento"]["doc_root"][doc_root]:
            globalconfig["magento"]["doc_root"][doc_root]["local_xml"] = { }
        # else:
        #     print 'DEFINED: "local_xml" in globalconfig["magento"]["doc_root"][%s]' % doc_root
        #     print type(globalconfig["magento"]["doc_root"][doc_root]["local_xml"]
        
        #testvar = magento.open_local_xml(local_xml)
        # var_dict = magento.open_local_xml(local_xml)
        update(globalconfig["magento"]["doc_root"][doc_root]["local_xml"], magento.open_local_xml(doc_root))
        # redis_module_xml = os.path.join(docroot,"app","etc","modules","Cm_RedisSession.xml")
        # app/etc/modules/Cm_RedisSession.xml
        # globalconfig["magento"]["doc_root"][doc_root]["local_xml"]

        update(globalconfig["magento"]["doc_root"][doc_root], magento.db_cache_table(doc_root,globalconfig["magento"]["doc_root"][doc_root]))
    
        #if return_config:
        #    #globalconfig["magento"]["doc_root"][doc_root]["cache"]["cache_option_table"]
        #    globalconfig["magento"]["doc_root"].update(return_config)

    def MEMCACHE_DATA_GATHER():
        pass
    # memcache = MemcacheCtl()
    
    memcache_instances = memcache.instances(globalconfig.get("magento",{}).get("doc_root",{}))

    if not globalconfig.get("memcache") and memcache_instances:
        globalconfig["memcache"] = {}
    if memcache_instances:
        update(globalconfig["memcache"], memcache.get_all_statuses(memcache_instances))


    def REDIS_DATA_GATHER():
        pass
    # redis = RedisCtl()
    
    redis_instances = redis.instances(globalconfig.get("magento",{}).get("doc_root",{}))
    #pp.pprint(redis_instances)
    # print "1930 redis_instances"
    # pp.pprint(redis_instances)
    if not globalconfig.get("redis") and redis_instances:
        globalconfig["redis"] = {}
    if redis_instances:
        #fixme add redis password
        update(globalconfig["redis"], redis.get_all_statuses(redis_instances))
else:
    for i in globalconfig["errors"]:
        sys.stdout.write(i)
"""
{'/var/www/html':
    {
        'Mage.php': '/var/www/html/app/Mage.php',
        'mage_version':
        {
            'major': '1',
            'number': '',
            'patch': '0',
            'stability': '',
            'edition': 'EDITION_COMMUNITY',
            'version': '1.9.1.0',
            'minor': '9',
            'revision': '1'},
       'magento_version': 'Magento 1.9.1.0 EDITION_COMMUNITY',
       'magento_path': '/var/www/html'
    }
}
"""


# using this as a bookmark in the IDE
class OUTPUT(object):
    pass
"""
  ___  _   _ _____ ____  _   _ _____ 
 / _ \| | | |_   _|  _ \| | | |_   _|
| | | | | | | | | | |_) | | | | | |  
| |_| | |_| | | | |  __/| |_| | | |  
 \___/ \___/  |_| |_|    \___/  |_|  
"""                                    
################################################
# Output body for checking values below
################################################

print "FQDN: %s" % localfqdn

#if not args.silent:
def NGINX_PRINT():
    pass
################################################
# NGINX
################################################
# maxclients or number of processes is "worker_processes"
if "nginx" in globalconfig:
    nginx.figlet()
    if globalconfig.get("nginx",{}).get("version"):
        print globalconfig.get("nginx",{}).get("version")
    else:
        print "No nginx version?"
    if globalconfig.get("nginx",{}).get("sites"):
        print "nginx sites:"
        """
        
        "sites" : [
            blah :{
                'domains': [
                    'example.com', 'www.example.com new.example.com'
                    ],
                'config_file': '/etc/httpd/conf/httpd.conf',
                'doc_root': '/var/www/html',
                'listening': [
                    '*:80'
                    ]
            }
        ]
        """
        if globalconfig.get("nginx",{}).get("error"):
            sys.stderr.write("Errors: \n%s\n" % globalconfig["nginx"]["error"])
            error_collection.append("Errors: \n%s\n" % globalconfig["nginx"]["error"])
        
        print_sites(globalconfig["nginx"]["sites"])

        # memory profile
        if globalconfig.get("nginx",{}).get("basename") and globalconfig.get("nginx",{}).get("maxprocesses"):
            proc_name = globalconfig["nginx"]["basename"]
            proc_max = int(globalconfig["nginx"]["maxprocesses"])
            result = memory_estimate(proc_name)
            if result:
                memory_print(result, proc_name, proc_max)
        print

#globalconfig["nginx"]["maxclients"]

def APACHE_PRINT():
    pass
################################################
# APACHE
################################################
if "apache" in  globalconfig:
    apache.figlet()
    if globalconfig.get("apache",{}).get("version"):
        print "Apache version: %s" % globalconfig.get("apache",{}).get("version")
    else:
        print "No apache version?"
    if globalconfig.get("apache",{}).get("sites"):
        print "Apache sites:"
        """
        28 Oct 2015
        {'domains':
        ['example.com', 'www.example.com new.example.com'],
        'config_file': '/etc/httpd/conf/httpd.conf',
        'doc_root': '/var/www/html',
        'listening': ['*:80']}
        """
        print_sites(globalconfig["apache"]["sites"])
        
        # memory profile
        if "basename" in globalconfig["apache"] and "maxprocesses" in globalconfig["apache"]:
            proc_name = globalconfig["apache"]["basename"]
            proc_max = globalconfig["apache"]["maxprocesses"]
            result = memory_estimate(proc_name)
            if result:
                memory_print(result, proc_name, proc_max)
        print "\n"


#globalconfig["nginx"]["maxclients"]

def PHP_FPM_PRINT():
    pass
################################################
# PHP-FPM
################################################
# maxclients is per stanza, and is pm.max_children
# for real numbers for calculation, I'll need to sum them all
if "php-fpm" in globalconfig:
    phpfpm.figlet()
    if globalconfig.get("php-fpm",{}).get("version"):
        print "php-fpm version: %s" % globalconfig.get("php-fpm",{}).get("version")
    else:
        print "No php version?"
    print "php-fpm pools:"
    for one in globalconfig["php-fpm"]:
        if type(globalconfig["php-fpm"][one]) is dict:
            print "%s" % (one,)
    #for one in sorted(globalconfig["php-fpm"]):
    #    print "%s %r\n" % (one,globalconfig["php-fpm"][one])

    print
    # memory profile
    print "php-fpm memory profile:"
    if globalconfig.get("php-fpm",{}).get("basename") and globalconfig.get("php-fpm",{}).get("maxprocesses"):
        proc_name = globalconfig["php-fpm"]["basename"]
        proc_max = int(globalconfig["php-fpm"]["maxprocesses"])
        result = memory_estimate(proc_name)
        if result:
            memory_print(result, proc_name, proc_max)

#globalconfig["nginx"]["maxclients"]

def MAGENTO_PRINT():
    pass
################################################
# Magento
################################################

if globalconfig.get("magento",{}).get("doc_root"):
    magento.figlet()
    print "\nMagento versions installed:"
    if globalconfig.get("magento",{}).get("doc_root"):
        for key, value in globalconfig["magento"]["doc_root"].iteritems():
            print "-" * 60
            print "Magento path: %s" % key
            print "Version: %s" % value["magento_version"]
            print
            # database settings
            skip = ["pdoType","initStatements","model","type"]
            if value.get("local_xml",{}).get("db"):
                print "Database info"
                for k2,v2 in value["local_xml"]["db"].iteritems():
                    if k2 in skip:
                        continue
                    print "%s: %s" % (k2,v2)
                print
            # session cache settings
            skip = ["engine","disable_locking","compression_threshold",
                    "log_level","first_lifetime","bot_first_lifetime",
                    "bot_lifetime","compression_lib","break_after_adminhtml",
                    "break_after_frontend","connect_retries"
                    ]
            if value.get("local_xml",{}).get("session_cache",{}).get("session_save"):
                print "Session Cache engine: %s" % value.get("local_xml",{}).get("session_cache",{}).get("engine","EMPTY")
                print "Session Cache: %s" % value["local_xml"]["session_cache"]["session_save"]
                for k2,v2 in value["local_xml"]["session_cache"].iteritems():
                    if k2 in skip:
                        continue
                    print "%s: %s" % (k2,v2)
                print
            # object cache settings
            skip = ["engine","compress_tags","use_lua",
                    "automatic_cleaning_factor","force_standalone",
                    "compress_data","compress_threshold",
                    "compression_lib","connect_retries"
                    ]
            if value.get("local_xml",{}).get("object_cache",{}).get("backend"):
                print "Object Cache engine: %s" % value.get("local_xml",{}).get("object_cache",{}).get("engine","EMPTY")
                print "Object Cache: %s" % value.get("local_xml",{}).get("object_cache",{}).get("backend","EMPTY")
                for k2,v2 in value["local_xml"]["object_cache"].iteritems():
                    if k2 in skip:
                        continue
                    print "%s: %s" % (k2,v2)
                print
            # full page cache settings
            skip = ["engine","connect_retries","force_standalone",
                    "compress_data"
                    ]
            if value.get("local_xml",{}).get("full_page_cache",{}).get("backend"):
                print "Full Page Cache engine: %s" % value.get("local_xml",{}).get("full_page_cache",{}).get("engine","EMPTY")
                print "Full Page Cache: %s" % value.get("local_xml",{}).get("full_page_cache",{}).get("backend","EMPTY")
                for k2,v2 in value["local_xml"]["full_page_cache"].iteritems():
                    if k2 in skip:
                        continue
                    print "%s: %s" % (k2,v2)
                print
            if value.get("cache",{}).get("cache_option_table"):
                print "cache_option_table:\n%s" % value["cache"]["cache_option_table"]
            print
"""
    pp.pprint(globalconfig["magento"]["doc_root"])
This output is flawed because local.xml was not configured correctly
{   '/var/www/vhosts/domain.com': {   'Mage.php': '/var/www/vhosts/domain.com/app/Mage.php',
                                             'local_xml': {   'db': {   'active': '1',
                                                                        'db/table_prefix': None,
                                                                        'dbname': 'new_mangento',
                                                                        'host': '172.24.1.1',
                                                                        'initStatements': 'SET NAMES utf8',
                                                                        'model': 'mysql4',
                                                                        'password': 'password',
                                                                        'pdoType': None,
                                                                        'type': 'pdo_mysql',
                                                                        'username': 'magentouser2'},
                                                              'filename': '/var/www/vhosts/domain.com/app/etc/local.xml',
                                                              'full_page_cache': {   'backend': 'Mage_Cache_Backend_Redis',
                                                                                     'compress_data': '0',
                                                                                     'connect_retries': '3',
                                                                                     'database': '0',
                                                                                     'force_standalone': '0',
                                                                                     'lifetimelimit': '57600',
                                                                                     'password': None,
                                                                                     'persistent': None,
                                                                                     'port': '6379',
                                                                                     'server': '127.0.0.1'},
                                                              'object_cache': {   'backend': 'memcached'},
                                                              'session_cache': {   'session_save': 'memcache',
                                                                                   'session_save_path': 'tcp://127.0.0.1:11211?persistent=0&weight=2&timeout=10&retry_interval=10'}},
                                             'mage_version': {   'edition': 'EDITION_ENTERPRISE',
                                                                 'major': '1',
                                                                 'minor': '14',
                                                                 'number': '',
                                                                 'patch': '0',
                                                                 'revision': '2',
                                                                 'stability': '',
                                                                 'version': '1.14.2.0'},
                                             'magento_path': '/var/www/vhosts/domain.com',
                                             'magento_version': 'Magento 1.14.2.0 EDITION_ENTERPRISE'}}

"""

def MEMCACHE_PRINT():
    pass
if globalconfig.get("memcache"):
    memcache.figlet()
    #pp.pprint(globalconfig.get("memcache"))
    for instance in globalconfig.get("memcache"):
        print "Server: %s" % instance
        print "Version: %s" % globalconfig["memcache"][instance].get('version',"")
        print "Bytes: %s" % globalconfig["memcache"][instance].get('bytes',"")
        print "Bytes Read: %s" % globalconfig["memcache"][instance].get('bytes_read',"")
        print "Bytes Written: %s" % globalconfig["memcache"][instance].get('bytes_written',"")
        print "Current items: %s" % globalconfig["memcache"][instance].get('curr_items',"")
        print "Evictions: %s" % globalconfig["memcache"][instance].get('evictions',"")
        print "Get hits: %s" % globalconfig["memcache"][instance].get('get_hits',"")
        print "Get misses: %s" % globalconfig["memcache"][instance].get('get_misses',"")
        print "Limit MaxBytes: %s" % globalconfig["memcache"][instance].get('limit_maxbytes',"")
        print
def REDIS_PRINT():
    pass
if globalconfig.get("redis"):
    redis.figlet()
    for instance in globalconfig.get("redis"):
        print "Server: %s" % instance

        # if this is ObjectRocket, it won't have Evicted Keys or Keyspace; it is less confusing to not display them
        print "Used memory peak: %s" % globalconfig.get("redis", {}).get(instance, {}).get("Memory",{}).get("used_memory_peak_human")
        if globalconfig.get("redis",{}).get(instance,{}).get("Stats",{}).get("evicted_keys"):
            print "Evicted keys: %s" % globalconfig.get("redis",{}).get(instance,{}).get("Stats",{}).get("evicted_keys")
        if globalconfig.get("redis",{}).get(instance,{}).get("Keyspace"):
            print "Keyspace:"
            for key,value in globalconfig.get("redis",{}).get(instance,{}).get("Keyspace",{}).iteritems():
                print "%s: %s" % (key,value)
            print
    #pp.pprint(globalconfig.get("redis"))
print
"""
 _____ ___  ____   ___  
|_   _/ _ \|  _ \ / _ \ 
  | || | | | | | | | | |
  | || |_| | |_| | |_| |
  |_| \___/|____/ \___/ 
"""
class TODO(object):
    pass

# Save the config as a json file
#filename = "config_dump.json"
if (not os.path.isfile(args.output) or args.force) and not args.jsonfile and JSON == True:
    globalconfig["errors"]=error_collection
    json_str=json.dumps(globalconfig)
    # with open(args.output,'w') as outfile:
    #     outfile.write( json_str )
    outfile = open(args.output,'w')
    outfile.write( json_str )
    outfile.close()

if args.printglobalconfig:
    print """
  ____ _       _           _  ____             __ _       
 / ___| | ___ | |__   __ _| |/ ___|___  _ __  / _(_) __ _ 
| |  _| |/ _ \| '_ \ / _` | | |   / _ \| '_ \| |_| |/ _` |
| |_| | | (_) | |_) | (_| | | |__| (_) | | | |  _| | (_| |
 \____|_|\___/|_.__/ \__,_|_|\____\___/|_| |_|_| |_|\__, |
                                                    |___/
"""
    pp.pprint(globalconfig)

if args.printjson and JSON == True:
    print json.dumps(globalconfig)
