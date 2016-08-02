#!/usr/bin/env python
"""
Magento is a trademark of Varien. Neither I nor these scripts are affiliated with or endorsed by the Magento Project or its trademark owners.

"""

"""
wget https://raw.githubusercontent.com/CharlesMcKinnis/ecommStackStatus/master/ecommStackStatus.py

git clone https://github.com/CharlesMcKinnis/ecommStackStatus.git
#dev branch
cd ecommStackStatus
git checkout -b dev origin/dev

To look at the json captured:
cat config_dump.json |python -m json.tool|less
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

* TODO things to add
We could get information similar to MySQL Buddy and display it, to name a few:
long_query_time
query_cache_size
join_buffer_size
table_open_cache
innodb_buffer_pool_size
innodb_buffer_pool_instances
innodb_log_buffer_size
query_cache_limit

* Magento report numbers for reports in the last 24-48 hours with date and time

* name json file by hostname and date+time

* I would like to load all xml in app/etc/ and overwrite values with local.xml so the config is complete

* Varnish detection and cache health
# ps -ef|grep [v]arnish
root     11893     1  0 Nov25 ?        00:05:35 /usr/sbin/varnishd -P /var/run/varnish.pid -a :80 -f /etc/varnish/default.vcl -T 192.168.100.168:6082 -t 120 -w 50,1000,120 -u varnish -g varnish -p cli_buffer=16384 -S /etc/varnish/secret -s malloc,10G
varnish  11894 11893  2 Nov25 ?        02:45:04 /usr/sbin/varnishd -P /var/run/varnish.pid -a :80 -f /etc/varnish/default.vcl -T 192.168.100.168:6082 -t 120 -w 50,1000,120 -u varnish -g varnish -p cli_buffer=16384 -S /etc/varnish/secret -s malloc,10G

* Add mysql branch to globalconfig, and parse "show variables;"
proposed structure:
mysql: {
    HOSTNAME: {
        port: "", # Do I need this? It is nearly always 3306
        username: "",
        password: "",
        variables: {
            `show variables` # parsed to key:value pairs
        }
    }
}

* MySQL max_connections, max_used_connections

* MySQL query cache, example values: query_cache_type=1, query_cache_size=256M, query_cache_limit=16M

* Check Magento for the Shoplift SUPEE-5344 vulnerability
find /var/www -wholename '*/app/code/core/Mage/Core/Controller/Request/Http.php' | xargs grep -L _internallyForwarded
If it returns results, assuming Magento is in /var/www, it is vulnerable.
-L Suppress normal output; instead print the name of each input file from which no output would normally have been printed.  The scanning will stop on the first match.

Check doc_root/app/code/core/Mage/Core/Controller/Request/Http.php
If it doesn't have _internallyForwarded it is probably vulnerable to shoplift

* Check Magento for SUPEE-7405

* Check for cron job, should be cron.sh NOT cron.php

* check php opcache
i.e.
Re-enabled PHP opcache in /etc/php.d/10-opcache.ini:
opcache.enable=1
Changed the "0" to a "1" on that line.
Stop nginx, restart php-fpm, start nginx.

* check mysql

* magento_root/shell/indexer.php --status
i.e.
2560M
2024M
Category Flat Data:                 Pending
Product Flat Data:                  Pending
Stock Status:                       Pending
Catalog product price:              Pending
Category URL Rewrites:              Pending
Product URL Rewrites:               Pending
URL Redirects:                      Pending
Catalog Category/Product Index:     Pending
Catalog Search Index:               Pending
Default Values (MANAdev):           Pending
Dynamic Categories:                 Running
Tag Aggregation Data:               Pending
SEO Schemas (MANAdev):              Pending
Product Attributes:                 Pending
SEO URL Rewrites (MANAdev):         Pending


DONE
* also need to check, if session cache is using redis - DONE 
app/etc/modules/Cm_RedisSessions.xml
value of <active> to true
* add hostname in globalconfig
* Parse this session_cache syntax for redis
Session Cache engine: unknown
Session Cache: redis
session_save: redis
session_save_path: tcp://192.168.100.200:6379?weight=2&timeout=2.5

From local.xml:
        <session_save><![CDATA[redis]]></session_save>
        <session_save_path><![CDATA[tcp://192.168.100.200:6379?weight=2&timeout=2.5]]></session_save_path>


"""
STACK_LIB_VERSION = 2016051601
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
    # try:
    #     import simplejson
    #     JSON = True
    # except ImportError:
    #     JSON = False
    #     sys.stderr.write("Data export omitted, module json and simplejson are not installed\n")
    #     sys.stderr.write("This is most common on RHEL 5 with python 2.4. run: yum install python-simplejson")
    #     error_collection.append("Data export omitted because the json module is not installed\n")
    JSON = False
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
        lines = iter(wholeconfig.splitlines())
        for line in lines:
            linenum += 1
            linecomp = line.strip().lower()
            # if the line opens < but doesn't close it with > there is probably a \ and newline
            # and it should be concat with the next line until it closes with >

            # if a line ends in \, it is continued on the next line
            while linecomp.endswith("\\"):
                linecomp = linecomp.strip("\\").strip()
                # read the next line
                line = lines.next()
                
                linenum += 1
                linecomp += " "
                linecomp += line.strip().lower()
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
        configfile_vars = {}
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
            # this is where I need to add variable parsing
            # if re \s*set\s+$(varname)\s+["']?(\S+)["']?;
            # nginxvars[group(1)] = group(2)
            nginxset = re.search("\s*set\s+$(varname)\s+[\"']?(\S+)[\"']?")
            configfile_vars[nginxset.group(1)] = nginxset.group(2)
            # if line contains \s$(varname)\s replace varname with nginxvars[group(1)]
            
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
        print "configfile_vars: %r" % configfile_vars
        # this section is so the same information shows up in nginx and apache, to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] =  []
        
        # pressing the whole web daemon config in to a specific framework so it is easier to work with
        for i in stanzas.keys():
            # fixes an error where i = 'error' and the contents are a string
            if type(stanzas[i]) is not list and type(stanzas[i]) is not dict:
                continue
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
            try:
                stanzas["maxprocesses"] = int(stanzas["worker_processes"][0])
            except ValueError:
                stanzas["maxprocesses"] = -1
    
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
        #mage["version"] = ".".join(filter(None,[mage["major"],mage["minor"],mage["revision"],mage["patch"],mage["stability"],mage["number"]]))
        mage["version"] = ".".join(filter(None,
                                          [
                                            mage.get("major"),
                                            mage.get("minor"),
                                            mage.get("revision"),
                                            mage.get("patch"),
                                            mage.get("stability"),
                                            mage.get("number")
                                           ]
                                          )
                                   )

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
            #print "935 doc_root_path %s mage_php_match %s" % (doc_root_path, mage_php_match)
            return_dict[doc_root_path] = {}
            mage = self.parse_version(mage_php_match)
            #print "938 os.path.dirname(mage_php_match) %r" % os.path.dirname(mage_php_match)
            head,tail = os.path.split(os.path.dirname(mage_php_match))
            #print "940 head %s tail %s" %(head,tail)
            return_dict[doc_root_path]["Mage.php"] = mage_php_match
            return_dict[doc_root_path]["magento_path"] = head
            return_dict[doc_root_path]["local_xml"] = { }
            return_dict[doc_root_path]["local_xml"]["filename"] = os.path.join(head, "app", "etc", "local.xml")
            return_dict[doc_root_path]["magento_version"] = "%s" % mage["version"]
            if mage["edition"]:
                return_dict[doc_root_path]["magento_version"] += " %s" % mage["edition"]
            return_dict[doc_root_path]["mage_version"] = mage
        return(return_dict)
    
    def open_local_xml(self, doc_root, config_node):
        """
        provide the filename (absolute or relative) of local.xml
        
        This function opens the file as an XML ElementTree
        
        returns: dict with db and cache information
        """
        # BROKEN
#        filename = os.path.join(doc_root,"app","etc","local.xml")
        filename = config_node["local_xml"]["filename"]
        #print "962 %s" % filename
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
        # print "resources %r" % resources
        # print "xml_config_node %r" % local_xml.get(section,{}).get(xml_config_node,"").lower()
        # print "xml_config_single %r" % local_xml.get(section,{}).get(xml_config_single,"")
        # if resources is not None:
        #     print "962 resources is not None"
        # if (local_xml.get(section,{}).get(xml_config_node,"").lower() == "redis"
        #     and "tcp://" in local_xml.get(section,{}).get(xml_config_single,"")):
        #     print "966 xml config node == redis and tcp in xml_config_single"
        if resources is not None or (local_xml.get(section,{}).get(xml_config_node,"").lower() == "redis"
                                     and "tcp://" in local_xml.get(section,{}).get(xml_config_single,"")):
            local_xml[section]["engine"] = "redis"
            redis_module_xml = os.path.join(doc_root,"app","etc","modules","Cm_RedisSession.xml")
            #print "908 redis module xml: %s" % redis_module_xml
            # app/etc/modules/Cm_RedisSession.xml
            # xml config/modules/Cm_RedisSession/active
            try:
                # print "969 Cm_RedisSession check"
                redis_tree = ET.ElementTree(file=redis_module_xml)
                Cm_RedisSession = redis_tree.find("modules/Cm_RedisSession/active")
                if Cm_RedisSession is not None:
                    #print "opened Cm_RedisSession.xml"
                    if Cm_RedisSession.text is not None:
                        #print "and found %s" % Cm_RedisSession.text
                        local_xml[section]["Cm_RedisSession.xml active"] = Cm_RedisSession.text
                    else:
                        local_xml[section]["Cm_RedisSession.xml active"] = "Cm_RedisSession is present but the value is empty"
                else:
                    local_xml[section]["Cm_RedisSession.xml active"] = "Cm_RedisSession is not present"
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
        mysql = MysqlCtl()
        var_table_prefix = value.get("db/table_prefix","")
        var_dbname = value.get("dbname","")
        var_host = value.get("host","")
        var_username = value.get("username","")
        var_password = value.get("password","")
        output = mysql.db_query(value, "select * FROM `%s`.`%score_cache_option`;" % (var_dbname,var_table_prefix))
        # doc_root isn't used locally anymore? 14 Jan 2016
        #globalconfig["magento"]["doc_root"][doc_root]["cache"]["cache_option_table"]
        #doc_roots = globalconfig["magento"]["doc_root"]
        return_config = { }
        if not return_config.get("cache",{}).get("cache_option_table"):
            return_config = {"cache" : { "cache_option_table" : "" } } 
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
            sys.stderr.write("ERROR, one of these is none, ip: %s port: %s\n" % (ip,port))
            sys.exit(1)
        port = int(port)
        if kwargs.get("password") is not None:
            # print "1097 redis password found" #rmme
            reply = socket_client(ip,port,["AUTH %s\n" % kwargs["password"], "INFO\n"])
        else:
            # print "1100 redis password skipped" #rmme
            reply = socket_client(ip,port,"INFO\n")
            # print "1158"
        # print "1159 reply %r" % reply
        if reply:
            return(reply)
        else:
            return(None)
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
        # print "1130 get_all_statuses" #rmme
        #pp.pprint(instances) #rmme        
        for i in instances:
            host = instances[i]["host"]
            port = instances[i]["port"]
            password = instances.get(i,{}).get("password")
            # print "host %s" % host
            # print "port %s" % port
            # print "password %s" % password
            # [host, port] = i.split(":")
            if not return_dict.get(i):
                return_dict[i] = {}
            # print "1072 %r" % (i)
            # need to check for a password
            # password will be None if there wasn't one in the local.xml
            # I could just pass the None value through without checking because it is check for None in get_status
            if password and host and port:
                # print "1144 redis password, host and port"
                reply = self.get_status(host, port, password = password)
            elif host and port:
                # print "1147 redis host and port"
                reply = self.get_status(host, port)
            else:
                #print "1150 redis instance"
                #pp.pprint(instances[i])
                reply = None
            if reply:
                # print "1210"
                return_dict[i] = self.parse_status(reply)
        return(return_dict)
    def instances(self, doc_roots):
        #print "redis.instances doc_roots: %r" % doc_roots
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
        # redis_instances = set()
        redis_dict = {} # "host:port" : {host:"",port:"",password:""}
        for key, value in doc_roots.iteritems():
            pass
            if value.get("local_xml"):
                local_xml = value.get("local_xml",{})
                # print "1179 local_xml"
                # pp.pprint(local_xml)
            if local_xml.get("session_cache",{}).get("engine") == "redis":
                if local_xml.get("session_cache",{}).get("host") and local_xml.get("session_cache",{}).get("port"):
                    # print "1182 session_cache is redis"
                    stanza = "%s:%s" % (
                        local_xml.get("session_cache",{}).get("host"),
                        local_xml.get("session_cache",{}).get("port")
                    )
                    # redis_instances.add(stanza)
                    redis_dict[stanza] = {}
                    #if local_xml.get("session_cache",{}).get("host"):
                    redis_dict[stanza]["host"] = local_xml.get("session_cache",{}).get("host")
                    #if local_xml.get("session_cache",{}).get("port"):
                    redis_dict[stanza]["port"] = local_xml.get("session_cache",{}).get("port")
                    redis_dict[stanza]["password"] = local_xml.get("session_cache",{}).get("password")
                    #print "1098 redis_dict %r" % redis_dict
                elif "tcp://" in local_xml.get("session_cache",{}).get("session_save_path"):
                    result = re.match('tcp://([^:]+):(\d+)',
                    local_xml.get("session_cache",{}).get("session_save_path")
                    )
                    if result:
                        host = result.group(1)
                        port = result.group(2)
                        stanza = "%s:%s" % (host,port)
                        redis_dict[stanza] = {}
                        redis_dict[stanza]["host"] = host
                        redis_dict[stanza]["port"] = port
                        redis_dict[stanza]["password"] = None
            # OBJECT
            # for this doc_root, if the object cache is memcache, get the ip and port, and add it to the set
            # redis
            if local_xml.get("object_cache",{}).get("engine") == "redis":
                # print "1200 object_cace is redis"
                stanza = "%s:%s" % (
                    local_xml.get("object_cache",{}).get("server"),
                    local_xml.get("object_cache",{}).get("port")
                )
                # redis_instances.add(stanza)
                redis_dict[stanza] = {}
                redis_dict[stanza]["host"] = local_xml.get("object_cache",{}).get("server")
                redis_dict[stanza]["port"] = local_xml.get("object_cache",{}).get("port")
                redis_dict[stanza]["password"] = local_xml.get("object_cache",{}).get("password")
                #print "1115 redis_dict %r" % redis_dict

            # FULL PAGE CACHE
            # redis
            if local_xml.get("full_page_cache",{}).get("engine") == "redis":
                stanza = "%s:%s" % (
                    local_xml.get("full_page_cache",{}).get("server"),
                    local_xml.get("full_page_cache",{}).get("port")
                )
                # redis_instances.add(stanza)
                redis_dict[stanza] = {}
                #if local_xml.get("session_cache",{}).get("host"):
                redis_dict[stanza]["host"] = local_xml.get("full_page_cache",{}).get("server")
                #if local_xml.get("session_cache",{}).get("port"):
                redis_dict[stanza]["port"] = local_xml.get("full_page_cache",{}).get("port")
                redis_dict[stanza]["password"] = local_xml.get("full_page_cache",{}).get("password")
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
            # print "1144 %r" % (instance)
            # need to check for a password
            reply = self.get_status(ip, port)
            return_dict[instance] = self.parse_status(reply)
        return(return_dict)
    def instances(self, doc_roots):
        #print "memcache.instances doc_roots: %r" % doc_roots
        memcache_dict = {}
        memcache_instances = set()
        for key, doc_root_dict in doc_roots.iteritems():
            # for doc_root in doc_roots:
            #     doc_root_dict = globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{})

            # SESSION
            # for this doc_root, if the session cache is memcache, get the ip and port, and add it to the set
            # memcache
            if doc_root_dict.get("local_xml",{}).get("session_cache",{}).get("engine") == "memcache":
                result = re.match('tcp://([^:]+):(\d+)',
                    doc_root_dict["local_xml"].get("session_cache",{}).get("session_save_path")
                    )
                if result:
                    host = result.group(1)
                    port = result.group(2)
                    stanza = "%s:%s" % (host,port)
                    memcache_dict[stanza] = {"host": host, "port": port}
                    memcache_instances.add(stanza)
            # OBJECT
            # for this doc_root, if the object cache is memcache, get the ip and port, and add it to the set
            # memcache
            if doc_root_dict.get("local_xml",{}).get("object_cache",{}).get("engine") == "memcache":
                host = doc_root_dict.get("local_xml",{}).get("object_cache",{}).get("host")
                port = doc_root_dict.get("local_xml",{}).get("object_cache",{}).get("port")
                stanza = "%s:%s" % (host,port)
                memcache_dict[stanza] = {"host": host, "port": port}
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
        reply = socket_client(ip,port,"stats\n")
        return(reply)
    def db_query(self, dbConnInfo, sqlquery):
        # dbConnInfo = { "db/table_prefix", "dbname", "host", "username", "password" }

        output = ""

        var_table_prefix = dbConnInfo.get("db/table_prefix","")
        var_dbname = dbConnInfo.get("dbname","")
        var_host = dbConnInfo.get("host","")
        var_username = dbConnInfo.get("username","")
        var_password = dbConnInfo.get("password","")

        if (var_dbname and var_host and var_username and var_password ):
            conf = "mysql --table --user='%s' --password='%s' --host='%s' --execute='%s' 2>&1 " % (
                var_username,
                var_password,
                var_host,
                sqlquery
                )
            #sys.stderr.write("Querying MySQL...\n") #fixme --verbose?
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
        return(output)
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
        return_dict = {} # "host:port" : {host:"",port:"",password:""}
        for doc_root in doc_roots:
            if globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml"):
                xml_db = globalconfig.get("magento",{}).get("doc_root",{}).get(doc_root,{}).get("local_xml",{}).get("db",{})
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
            # print "1352 reply %s" % reply
        sock.close()
    except socket.error:
        sys.stderr.write("socket connect error host: %s port: %s" % (host,port))
        error_collection.append("socket connect error host: %s port: %s" % (host,port))
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
        except TypeError:
            e=""
            sys.stderr.write("TypeError %s\n" % (os.path.join('/proc', pid, 'exe')))
            continue
        except (IOError,OSError): # proc has already terminated, you may not be root
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
    if kwargs["recurse_count"] > 20:
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

    # print "1655 %r" % full_file_path(filename, base_path)
    # print "1656 %r" % files

    for onefile in files:
        # for each file in the glob (may be just one file), open it
        # try:
        onefile_handle = open(onefile, 'r')
        # print "1659 onefile_handle %r" % onefile_handle
        # onefile should always be a file
        if os.path.isfile(onefile):
            combined += "## START "+onefile+"\n"
        # else:
        #     print "1664 file isn't a file? " % onefile
        #     combined += "#1664 file isn't a file? " % onefile
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
        #print "#combined#"
        #print combined
        #print "#end#"
    return(combined)

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
    status = { "line_sum":0, "line_count":0, "biggest":0, "free_mem":0, "buffer_cache":0, "php_vsz-rss_sum":0 }

    #freeMem=`free|egrep '^Mem:'|awk '{print $4}'`
    conf = "free"
    p = subprocess.Popen(
        conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, err = p.communicate()
    if not output:
        raise NameError("Fail: %s" % err)
    lines = output.splitlines()
    # The calculation is using RSS, and free memory.
    # There are buffers and cache used by the process, and that throws off the calculation
    for line in lines:
        result = re.match('(Mem:)\s+(\S+)\s+(\S+)\s+(\S+)', line)
        if result:
            status["free_mem"] = int(result.group(4))
            continue
        result = re.match('(\+/-\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
        if result:
            status["buffer_cache"] = int(result.group(4))
            #print "1552 buffer_cache"
            #print status["buffer_cache"]
            break

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
    # print
    # print "If we also allowed %s to use the memory currently used for buffers and cache by %s:" % (proc_name,proc_name)
    # print "avg 100% danger   avg 80% warning   lrg 100% cautious   lrg 80% safe"
    # print "     %3d                %3d                %3d              %3d" % (
    #     int(( (result["line_sum"]+result["free_mem"]+result["php_vsz-rss_sum"]) / (result["line_sum"]/result["line_count"]) )),
    #     int(( (result["line_sum"]+result["free_mem"]+result["php_vsz-rss_sum"]) / (result["line_sum"]/result["line_count"]) ) * .8),
    #     int( (result["line_sum"]+result["free_mem"]+result["php_vsz-rss_sum"]) / result["biggest"]),
    #     int( (result["line_sum"]+result["free_mem"]+result["php_vsz-rss_sum"]) / result["biggest"] * .8)
    #     )
    
    
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
    #for k, v in u.iteritems():
    for k in u:
        # if isinstance(v, collections.Mapping):
        if isinstance(u[k], dict):
            r = update(d.get(k, {}), u[k])
            d[k] = r
        else:
            d[k] = u[k]
    return d
