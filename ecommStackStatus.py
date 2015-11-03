#!/usr/bin/env python2
"""
Magento is a trademark of Varien. Neither I nor these scripts aret affiliated with or endorsed by the Magento Project or its trademark owners.

"""

"""
wget https://raw.githubusercontent.com/CharlesMcKinnis/EcommStatusTuning/master/ecommStackStatus.py
git clone https://github.com/CharlesMcKinnis/EcommStatusTuning.git
"""
import re
import glob
import subprocess
import sys
import os
#import yaml
import fnmatch
import json
import xml.etree.ElementTree as ET
import pprint

pp = pprint.PrettyPrinter(indent=4)

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
            #print " is not installed!!!"
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
                #print "filechain: %r" % filechange
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
                #print "stanza_chain len %d" % len(stanza_chain)
            result = re.match('</', linecomp )
            if result:
                stanza_count -= 1
                stanza_chain.pop()
    
    
            # base configuration
            if stanza_count == 0:
                keywords = base_keywords + vhost_keywords
                if not "config" in stanzas:
                    stanzas["config"] = { }
                stanzas["config"].update(kwsearch(keywords,linecomp))
    
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
                    #print line
                    if not "prefork" in stanzas:
                        stanzas["prefork"] = {}
                    stanzas["prefork"].update(kwsearch(prefork_keywords,line,single_value=True))
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
                    #print line
                    if not "worker" in stanzas:
                        stanzas["worker"] = {}
                    stanzas["worker"].update(kwsearch(worker_keywords,linecomp,single_value=True))
                    continue
    
            # virtual host matching
            result = re.match('<virtualhost\s+([^>]+)', linecomp, re.IGNORECASE )
            if result:
                #print "matched vhost %s" % result.group(1)
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
                #print "in a vhost file %s: %s" % (stanzas[server_line]["config_file"][-1],line.strip())
                #print kwsearch(keywords,line.strip() )
                stanzas[server_line].update( kwsearch(keywords,line.strip() ) )
                """
                for word in keywords:
                    #print "word: %s in line: %s" % (word,line.strip("\s\t;"))
                    result = re.search("\s*({0})\s*(.*)".format(word), line.strip("\s\t;"), re.IGNORECASE)
                    if result:
                        #print "keyword match %s" % word
                        if not word in stanzas[server_line]:
                            stanzas[server_line][word] = []
                        stanzas[server_line][word] += [result.group(2)]
                """
            # closing VirtualHost
            result = re.match('</VirtualHost\s+([^>]+)', linecomp, re.IGNORECASE )
            if result:
                vhost_start = -1
                continue
            # end virtual host matching
    
        # this section is so the same information shows up in nginx and apache, to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] =  []
        #print "parsed apache: %r" % stanzas
        for i in stanzas.keys():
            #print "i %s" %i
            #print "pre-match %r" % stanzas[i]
            if ("documentroot" in stanzas[i]) or ("servername" in stanzas[i]) or ("serveralias" in stanzas[i]) or ("virtualhost" in stanzas[i]):
                #print "matched %r" % stanzas[i]
                configuration["sites"].append( { } )
                #configuration["sites"].append( {
                #    "domains" : [],
                #    "doc_root" : "",
                #    "config_file" : "",
                #    "listening" : [] } )
                # "customlog", "errorlog"
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

        stanzas.update(configuration)
        if not "maxclients" in stanzas["config"]:
            mpm = self.get_mpm().lower()
            #print "mpm: %r" % mpm
            #print "config %r" % stanzas["prefork"]
            if mpm == "prefork":
                if "prefork" in stanzas:
                    if "maxclients" in stanzas["prefork"]:
                        #print "prefork maxclients %s" % stanzas["prefork"]["maxclients"]
                        stanzas["maxclients"] = int(stanzas["prefork"]["maxclients"])
            elif mpm == "event":
                if "event" in stanzas:
                    if "maxclients" in stanzas["event"]:
                        #print "event maxclients %s" % stanzas["event"]["maxclients"]
                        stanzas["maxclients"] = int(stanzas["event"]["maxclients"])
            elif mpm == "worker":
                if "worker" in stanzas:
                    if "maxclients" in stanzas["worker"]:
                        #print "worker maxclients %s" % stanzas["worker"]["maxclients"]
                        stanzas["maxclients"] = int(stanzas["worker"]["maxclients"])
            else:
                print "Could not identify mpm in use."
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
            #print "nginx is not installed!!!"
            sys.exit(1)

    def get_bin(self):
        """
        :returns: nginx binary location
        """
        try:
            return self.get_conf_parameters()['--sbin-path']
        except:
            #print "nginx is not installed!!!"
            sys.exit(1)

    def get_pid(self):
        """
        :returns: nginx pid location which is required by nginx services
        """

        try:
            return self.get_conf_parameters()['--pid-path']
        except:
            #print "nginx is not installed!!!"
            return()

    def get_lock(self):
        """
        :returns: nginx lock file location which is required for nginx services
        """

        try:
            return self.get_conf_parameters()['--lock-path']
        except:
            #print "nginx is not installed!!!"
            return()

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
                    stanzas["error"] = "This script does not consistently support opening { and closing } stanzas on the same line.\n"
                stanzas["error"] += "line %d: %s\n" % (linenum,line.strip())
            stanza_count+=len(re.findall('{',line))
            stanza_count-=len(re.findall('}',line))
            result = re.match("(\S+)\s*{",linecomp)
            if result:
                stanza_chain.append({ "linenum" : linenum, "title" : result.group(1) })
                #print "stanza_chain len %d" % len(stanza_chain)
            if len(re.findall('}',line)) and len(stanza_chain) > 0:
                stanza_chain.pop()
            #print "stanza_chain len %d" % len(stanza_chain)
    
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
                stanzas[server_line].update(kwsearch(keywords,line))
                keywords = server_keywords_split
                if not server_line in stanzas:
                    stanzas[server_line] = { }
                if not "server_name" in stanzas[server_line]:
                    stanzas[server_line]["server_name"] = []
                if kwsearch(["server_name"],line):
                    stanzas[server_line]["server_name"] += kwsearch(["server_name"],line)["server_name"][0].split()
                """
                for word in keywords:
                    result = re.match("\s*({0})\s*(.*)".format(word), line.strip("\s\t;"), re.IGNORECASE)
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
                #print ""
            # end server { section
            
            # keywords is a list of keywords to search for
            # look for keywords in the line
            # pass the keywords to the function and it will extract the keyword and value
            keywords = ["worker_processes"]
            stanzas.update(kwsearch(keywords,line))
    
        # this section is so the same information shows up in nginx and apache, to make it easier to make other calls against the info
        # think magento location
        configuration = {}
        configuration["sites"] =  []
        #print "parsed apache: %r" % stanzas
        
        # pressing the whole web daemon config in to a specific framework so it is easier to work with
        for i in stanzas.keys():
            #print "i %s" %i
            #print "pre-match %r" % stanzas[i]
            if ("root" in stanzas[i]) or ("server_name" in stanzas[i]) or ("listen" in stanzas[i]):
                #print "matched %r" % stanzas[i]
                # "access_log", "error_log"
                configuration["sites"].append( { } )
                if "server_name" in stanzas[i]:
                    if not "domains" in configuration["sites"][-1]: configuration["sites"][-1]["domains"] = []
                    configuration["sites"][-1]["domains"] += stanzas[i]["server_name"]
                if "listen" in stanzas[i]:
                    if not "listening" in configuration["sites"][-1]: configuration["sites"][-1]["listening"] = []
                    configuration["sites"][-1]["listening"] += stanzas[i]["listen"]
                if "root" in stanzas[i]:
                    configuration["sites"][-1]["doc_root"] = stanzas[i]["root"][0]
                if "config_file" in stanzas[i]:
                    configuration["sites"][-1]["config_file"] = stanzas[i]["config_file"][0]
                if "access_log" in stanzas[i]:
                    configuration["sites"][-1]["access_log"] = stanzas[i]["access_log"][0]
                if "error_log" in stanzas[i]:
                    configuration["sites"][-1]["error_log"] = stanzas[i]["error_log"][0]
        stanzas.update(configuration)
        if "worker_processes" in stanzas:
            #print "stanza worker_process: %r" % stanzas["worker_processes"]
            stanzas["maxclients"] = int(stanzas["worker_processes"][0])
    
        return stanzas

class phpfpmCtl(object):
    def __init__(self,**kwargs):
        self.kwargs = kwargs
        if not "exe" in self.kwargs:
            self.kwargs["exe"] = "php-fpm"
            
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
                #print "stanza match ln 541: %r" % result.group(1)
                stanza_chain.append({ "linenum" : linenum, "title" : result.group(1) })
                #print "stanza_chain len %d" % len(stanza_chain)
            else:
                #print "else line: %r" % line.strip()
                #match not spaces or =, then match = and spaces, then not spaces
                result = re.match('([^=\s]+)\s*=\s*(\S+)', linecomp )
                if result:
                    key = result.group(1)
                    value = result.group(2)
                    #print "Current stanza: %r" % stanza_chain
                    #print "stanza chain -1 %r" % stanza_chain[-1]
                    #print "stanza title -1 %r" % stanza_chain[-1]["title"]
                    #print "stanzas %r" % stanzas
                    if not stanza_chain[-1]["title"] in stanzas:
                        stanzas[stanza_chain[-1]["title"]] = {}
                    stanzas[stanza_chain[-1]["title"]][key] = value
        stanzas["maxclients"] = 0
        #print "stanzas: %r" % stanzas
        for one in stanzas:
            #print "%s %r\n" % (one,stanzas[one])
            #print "one: %r stanzas[one]: %r" % (one,stanzas[one])
            if type(stanzas[one]) is dict:
                if "pm.max_children" in stanzas[one]:
                    stanzas["maxclients"] += int(stanzas[one]["pm.max_children"])
        return(stanzas)

class MagentoCtl(object):
    
    def parse_version(self, mage_php_file):
        mage = {}
        file_handle = open(mage_php_file, 'r')
        for line in file_handle:
            result = re.match("static\s+private\s+\$_currentEdition\s*=\s*self::([^\s;]+);", line.strip(), re.IGNORECASE )
            if result:
                mage["edition"] = result.group(1)
            #result = re.match("public static function getVersionInfo\(\)", line.strip(), re.IGNORECASE)
            if "public static function getVersionInfo()" in line:
                line = file_handle.next() # {
                line = file_handle.next() # return array(
                while not ");" in line:
                    line = file_handle.next()
                    result = re.match("'([^']+)'\s*=>\s*'([^']*)'", line.strip())
                    if result:
                        mage[result.group(1)] = result.group(2)
                break
        file_handle.close()
        # join them with periods, unless they are empty, then omit them
        mage["version"] = ".".join(filter(None,[mage["major"],mage["minor"],mage["revision"],mage["patch"],mage["stability"],mage["number"]]))
        return(mage)
    
    def localxml(self, local_xml_file):
        pass
    def find_mage_php(self,doc_roots):
        return_dict = {}
        for doc_root_path in globalconfig["doc_roots"]:
            # with nginx and apache, we have docroot for web paths
            # we need to search those for Mage.php and local.xml
            #magento = MagentoCtl()
            
            #search_path = one # docroot
            mage_php_matches = []
            for root, dirnames, filenames in os.walk(doc_root_path):
                for filename in fnmatch.filter(filenames, 'Mage.php'):
                    mage_php_matches.append(os.path.join(root, filename))
                    #print "652 %r %r %r" % (root,dirnames,filenames)
        
            if len(mage_php_matches) > 1:
                print "There are multiple Mage.php files in the Document Root. Choosing the shortest path." #breakme! Using the one with the smallest path."
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
        #magento = MagentoCtl()
        #print "668 %r" % mage_files
        for doc_root_path, mage_php_match in mage_files.iteritems():
            return_dict[doc_root_path] = {}
            mage = self.parse_version(mage_php_match)
            head,tail = os.path.split(os.path.dirname(mage_php_match))
            return_dict[doc_root_path]["Mage.php"] = mage_php_match
            return_dict[doc_root_path]["magento_path"] = head
            return_dict[doc_root_path]["local_xml"] = os.path.join(head, "app", "etc", "local.xml")
            return_dict[doc_root_path]["magento_version"] = "Magento %s %s" % (mage["version"],mage["edition"])
            return_dict[doc_root_path]["mage_version"] = mage
        return(return_dict)
    
    def open_local_xml(self, filename):
        """
        provide the filename (absolute or relative) of local.xml
        
        returns: dict with db and cache information
        """
        try:
            tree = ET.ElementTree(file=filename)
        except:
            sys.stdout.write("Could not open file %s\n" % filename)
            sys.exit(1)

        #tree = ET.ElementTree(file='local.xml')
        #tree = ET.ElementTree(file='local-memcache.xml')
        local_xml = {}
        
        section = "db"
        xml_parent_path = 'global/resources'
        xml_config_node = 'db/table_prefix'
        xml_config_section = 'default_setup/connection'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
        
        section = "session_cache"
        xml_parent_path = 'global'
        xml_config_node = 'session_save'
        xml_config_section = 'redis_session'
        xml_config_single = 'session_save_path'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section, xml_config_single = 'session_save_path'))
        
        section = "object_cache"
        xml_parent_path = 'global/cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
        
        section = "full_page_cache"
        xml_parent_path = 'global/full_page_cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        xml_config_single = 'slow_backend'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section, xml_config_single = 'slow_backend'))
        
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
        #print tree, section, xml_parent_path, xml_config_node, xml_config_section
        local_xml = {}
        # full page cache (FPC) - redis
        #section = "full_page_cache"
        #print "\nsection: %s" % section
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
        #print resources
        if resources is not None:
            i = resources.find(xml_config_node)
        else:
            i = None
        if i is not None:
            #print "%s: %s" % (xml_config_node,i.text)
            local_xml[section][xml_config_node] = i.text
        # configuration
        if resources.find(xml_config_section) is not None:
            for i in resources.find(xml_config_section):
                #print "%s: %s" % (i.tag,i.text)
                local_xml[section][i.tag] = i.text
                
        if xml_config_single:
            if resources.find(xml_config_single) is not None:
                i = resources.find(xml_config_single)
                #print "%s: %s" % (i.tag,i.text)
                local_xml[section][i.tag] = i.text
        return local_xml

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
        #print pid, ppid, pscmd, psexe
        # fixme
        # if the exe has been deleted (i.e. through an rpm update), the exe will be "/usr/sbin/nginx (deleted)"
        if psexe:
            if re.search('\(deleted\)', psexe):
                # if the exe has been deleted (i.e. through an rpm update), the exe will be "/usr/sbin/nginx (deleted)"
                #print "WARNING: %s is reporting the binary running is deleted"
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
        print "Too many recursions while importing %s, the config is probably a loop." % filename
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
    #print "full path to file: %s" % full_file_path(filename)
    #print "globbing %r" % full_file_path(filename, base_path)
    files = glob.iglob( full_file_path(filename, base_path) ) # either an absolute path to a file, or absolute path to a glob
    #print "%r" % files
    combined = ""

    for onefile in files:
        #print "onefile: %r" % onefile
        # for each file in the glob (may be just one file), open it
        try:
            onefile_handle = open(onefile, 'r')
            # onefile should always be a file
            if os.path.isfile(onefile):
                #print "STA onefile: %s" % onefile
                combined += "## START "+onefile+"\n"
        except:
            return()

        # go through the file, line by line
        # if it has an include, go follow it
        for line in onefile_handle:
            result = re.match(keyword_regex, line.strip(), re.IGNORECASE )
            #result = re.match('(include.*)', line.strip(), re.I | re.U )
            # if it is an include, remark out the line,
            # figure out the full filename
            # and import it inline
            if result:
                #print "nested! %s" % result.group(1)
                combined += "#"+line+"\n"
                nestedfile = full_file_path(result.group(1), base_path)
                #print "nestedfile: %r" % nestedfile
                #print "line %r" % line.strip()
                combined += importfile(nestedfile, keyword_regex, **kwargs)
            else:
                combined += line
        # END of the file import, if it was a file and not a glob, make the ending. onefile should always be a file
        if os.path.isfile(onefile):
            #print "END onefile: %s" % onefile
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
        result = re.match("({0})\s*(.*)".format(word), line.strip(), re.IGNORECASE)
        #result = re.search("\s*(%s)\s*(.*)" % word, line.strip(), re.IGNORECASE)
        #result = re.search("\s*(%s)\s*(.*)" % '|'.join(map(str,keywords)), line.strip(), re.IGNORECASE) # this way, without the for loop took 10-12 times as long to run
        if result:
            #print "keyword match %s" % word
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
    print "Average memory per process: %d KB will use %d KB if max clients %d is reached." % (result["line_sum"]/result["line_count"], int(result["line_sum"] / result["line_count"] * proc_max), proc_max)
    print "Largest process: %d KB will use %d KB if MaxClients is reached.\n" % (result["biggest"], result["biggest"]*proc_max)
    #print "Based on the largest process, use this as a health check: %d" % (int(
    #    (result["free_mem"]+result["line_sum"]) - (result["biggest"]*proc_max) / result["biggest"]
    #    ))
    # red if proc_max > int( (result["line_sum"]+result["free_mem"]) / result["biggest"] )
    # green elif proc_max <= int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
    # yellow else
    #print "Positive numbers may mean you can have more clients. Negative numbers mean you are overcommited."
    #print "See below for numbers advice.\n"
    print "What should I set max clients to?"
    print "The safe value would be to use the largest process, and commit 80%% of memory: %d" % int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
    #print "If you use the average size, and commit 100%% of memory: %d or 80%%: %d" % (
    #    int( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) ),
    #    int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) ) * .8)
    #    )
    print
    print "Current maximum clients: %d" % proc_max
    print "avg 100% danger   avg 80% warning   lrg 100% cautious   lrg 80% safe"
    print "     %3d                %3d                %3d              %3d" % (
        int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) )),
        int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) ) * .8),
        int( (result["line_sum"]+result["free_mem"]) / result["biggest"]),
        int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
        )
    # print "How many max clients you may be able to handle based on the average size? %d" % (
    #     int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) )*.8)
    #     )
    # print "How many max clients you can handle based on largest process and 100%% commit? %d" % int( (result["line_sum"]+result["free_mem"]) / result["biggest"] )
    #print
    #print "A safe maximum clients based on the largest process, free memory and 80%% commit? %d" % int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)

def print_sites(localconfig):
    for one in sorted(localconfig):
        if "domains" in one:
            print "Domains: %s" % "  ".join(one["domains"])
        if "listening" in one:
            print "listening: %r" % ", ".join(one["listening"])
            #print "Listening on: %s" % " ".join(one["listening"])
        if "doc_root" in one:
            print "Doc root: %s" % one["doc_root"]
        if "config_file" in one:
            print "Config file: %s" % one["config_file"]
        if "access_log" in one:
            print "Access log: %s" % one["config_file"]
        if "error_log" in one:
            print "Error log: %s" % one["config_file"]

"""
need to check directory permissions
[root@localhost vhosts]# ll
total 4
drwxrwxr-x 3 user user 4096 Sep 15 17:11 example.com
"""
# these are the daemon executable names we are looking for
daemons = daemon_exe(["httpd", "apache2", "nginx", "bash", "httpd.event", "httpd.worker", "php-fpm", "mysql", "mysqld"])
for i in daemons:
    #print "%r" % daemons[i]
    if "error" in daemons[i]:
        sys.stderr.write(daemons[i]["error"] + "\n")

"""
for one in daemons:
    print "%s: %r\n" % (one,daemons[one])
"""
#pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(daemons)
globalconfig = {}
"""
 ____    _  _____  _       ____    _  _____ _   _ _____ ____  
|  _ \  / \|_   _|/ \     / ___|  / \|_   _| | | | ____|  _ \ 
| | | |/ _ \ | | / _ \   | |  _  / _ \ | | | |_| |  _| | |_) |
| |_| / ___ \| |/ ___ \  | |_| |/ ___ \| | |  _  | |___|  _ < 
|____/_/   \_\_/_/   \_\  \____/_/   \_\_| |_| |_|_____|_| \_\                                                           
"""
class DATA_GATHER():
    pass
# using this as a bookmark in the IDE
def APACHE_FPM_DATA_GATHER():
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
    print "Apache is not running"

if apache_exe:
    try:
        apache_conf_file = apache.get_conf()
        apache_root_path = apache.get_root()
        apache_mpm = apache.get_mpm()
    except:
        print "There was an error getting the apache daemon configuration"
        apache_conf_file = ""
        apache_root_path = ""
    #    apache_root_path = "/home/charles/Documents/Rackspace/ecommstatustuning/etc/httpd"
    #    apache_conf_file = "conf/httpd.conf"
    if apache_conf_file and apache_root_path:
        print "Using config %s" % apache_root_path+apache_conf_file
        wholeconfig = importfile(apache_conf_file, '\s*include\s+(\S+)', base_path = apache_root_path)
        apache_config = apache.parse_config(wholeconfig)

        if not "apache" in globalconfig:
            globalconfig["apache"] = {}
        globalconfig["apache"] = apache_config
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
def NGINX_FPM_DATA_GATHER():
    pass
################################################
# NGINX
################################################
if not "nginx" in daemons:
    print "nginx is not running"
else:
    nginx = nginxCtl(exe = daemons["nginx"]["exe"])
    try:
        nginx_conf_file = nginx.get_conf()
    except:
        print "There was an error getting the nginx daemon configuration"
        #nginx_conf_file = "/home/charles/Documents/Rackspace/ecommstatustuning/etc/nginx/nginx.conf"
        nginx_conf_file = ""
    if nginx_conf_file:
        print "Using config %s" % nginx_conf_file
        
        # configuration fetch and parse
        wholeconfig = importfile(nginx_conf_file, '\s*include\s+(\S+);')
        nginx_config = nginx.parse_config(wholeconfig)
        
        if not "nginx" in globalconfig:
            globalconfig["nginx"] = {}
        globalconfig["nginx"] = nginx_config
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
    print "php-fpm is not running"
else:
    #print "one: %r stanzas[one]: %r" % (one,stanzas[one])

    print
    phpfpm = phpfpmCtl(exe = daemons["php-fpm"]["exe"])
    try:
        phpfpm_conf_file = phpfpm.get_conf()
    except:
        print "There was an error getting the php-fpm daemon configuration"
        phpfpm_conf_file = ""
    if phpfpm_conf_file:
        #wholeconfig = importfile("/etc/php-fpm.conf", '\s*include[\s=]+(\S+)')
        wholeconfig = importfile(phpfpm_conf_file, '\s*include[\s=]+(\S+)')
        phpfpm_config = phpfpm.parse_config(wholeconfig)
        
        if not "php-fpm" in globalconfig:
            globalconfig["php-fpm"] = {}
        globalconfig["php-fpm"] = phpfpm_config
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
if "sites" in globalconfig.get("apache",{}):
    for one in globalconfig["apache"]["sites"]:
        if "doc_root" in one:
            doc_roots.add(one["doc_root"])
if "sites" in globalconfig.get("nginx",{}):
    for one in globalconfig["nginx"]["sites"]:
        if "doc_root" in one:
            doc_roots.add(one["doc_root"])
#if not "doc_roots" in globalconfig:
#    globalconfig["doc_roots"] = set()
globalconfig["doc_roots"] = list(doc_roots)
#print "doc_roots %r" % globalconfig["doc_roots"]


magento = MagentoCtl()
#print "%r" % magento
if not "magento" in globalconfig:
    globalconfig["magento"] = {}
# find mage.php files in document roots
try:
    mage_files = magento.find_mage_php(globalconfig["doc_roots"])
except:
    print "No Magento found in the web document roots"
    #print "mage files %r" % mage_files
# get Magento information from those Mage.php
try:
    print "1265"
    print type(magento.mage_file_info(mage_files))
    pp.pprint(magento.mage_file_info(mage_files))
    globalconfig["magento"]["doc_root"] = magento.mage_file_info(mage_files)
except:
    print "Failed to get magento information"

#print "Magento dictionary:"
#pp.pprint(globalconfig["magento"])

for doc_root in globalconfig["magento"]["doc_root"]:
    if not doc_root in globalconfig["magento"]["doc_root"]:
        globalconfig["magento"]["doc_root"][doc_root] = {}
    local_xml = os.path.join(doc_root,"app","etc","local.xml")
    if not "local_xml" in globalconfig["magento"]["doc_root"][doc_root]:
        globalconfig["magento"]["doc_root"][doc_root]["local_xml"] = {}
    
    #testvar = magento.open_local_xml(local_xml)
    #print "1252: %r" % testvar
    localdict = magento.open_local_xml(local_xml)
    print "doc_root: %r" % doc_root
    print type(globalconfig["magento"]["doc_root"][doc_root])
    print globalconfig["magento"]["doc_root"][doc_root]["local_xml"]
    print type(localdict)
    pprint(localdict)
    globalconfig["magento"]["doc_root"][doc_root]["local_xml"].update(magento.open_local_xml(local_xml))
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
class OUTPUT():
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

def NGINX_PRINT():
    pass
################################################
# NGINX
################################################
# maxclients or number of processes is "worker_processes"
if "nginx" in globalconfig:
    if "sites" in  globalconfig["nginx"]:
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
        
        print_sites(globalconfig["nginx"]["sites"])
        # for one in sorted(globalconfig["nginx"]["sites"]):
        #     if "domains" in one:
        #         print "Domains: %s" % "  ".join(one["domains"])
        #     if "listening" in one:
        #         print "listening: %r" % ", ".join(one["listening"])
        #         #print "Listening on: %s" % " ".join(one["listening"])
        #     if "doc_root" in one:
        #         print "Doc root: %s" % one["doc_root"]
        #     if "config_file" in one:
        #         print "Config file: %s" % one["config_file"]
        #     if "access_log" in one:
        #         print "Access log: %s" % one["config_file"]
        #     if "error_log" in one:
        #         print "Error log: %s" % one["config_file"]
        print # an empty line between sections
            #print "%r\n" % (one)
        #if "daemon" in globalconfig["nginx"]:
        #    print "nginx daemon config: %r" % globalconfig["nginx"]["daemon"]
        
        # memory profile
        if "basename" in globalconfig["nginx"] and "maxclients" in globalconfig["nginx"]:
            proc_name = globalconfig["nginx"]["basename"]
            proc_max = int(globalconfig["nginx"]["maxclients"])
            result = memory_estimate(proc_name)
            if result:
                memory_print(result, proc_name, proc_max)
        print "\n"

#globalconfig["nginx"]["maxclients"]

def APACHE_PRINT():
    pass
################################################
# APACHE
################################################
if "apache" in  globalconfig:
    if "sites" in  globalconfig["apache"]:
        print "Apache sites:"
        #print "globalconfig[apache][sites]: %r" % globalconfig["apache"]["sites"]
        """
        28 Oct 2015
        {'domains':
        ['example.com', 'www.example.com new.example.com'],
        'config_file': '/etc/httpd/conf/httpd.conf',
        'doc_root': '/var/www/html',
        'listening': ['*:80']}
        """
        print_sites(globalconfig["apache"]["sites"])
        # for one in sorted(globalconfig["apache"]["sites"]):
        #     out_string = "Domains:"
        #     if "domains" in one:
        #         print "Domains: %s" % "  ".join(one["domains"])
        #     if "listening" in one:
        #         print "Listening on: %s" % ", ".join(one["listening"])
        #     if "doc_root" in one:
        #         print "Doc root: %s" % one["doc_root"]
        #     if "config_file" in one:
        #         print "Config file: %s" % one["config_file"]
        print # an empty line between sections
        #if "daemon" in globalconfig["apache"]:
        #    print "Apache daemon config: %r" % globalconfig["apache"]["daemon"]
        #print "apache complete %r" % globalconfig["apache"] # ["config"]["maxclients"]
        
        # memory profile
        if "basename" in globalconfig["apache"] and "maxclients" in globalconfig["apache"]:
            proc_name = globalconfig["apache"]["basename"]
            proc_max = globalconfig["apache"]["maxclients"]
            result = memory_estimate(proc_name)
            #print "result %r" % result
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
    #print "php-fpm configs"
    print "php-fpm pools:"
    for one in globalconfig["php-fpm"]:
        if type(globalconfig["php-fpm"][one]) is dict:
            print "%s" % (one,)
    #for one in sorted(globalconfig["php-fpm"]):
    #    print "%s %r\n" % (one,globalconfig["php-fpm"][one])

    print
    # memory profile
    print "php-fpm memory profile:"
    if "basename" in globalconfig["php-fpm"] and "maxclients" in globalconfig["php-fpm"]:
        proc_name = globalconfig["php-fpm"]["basename"]
        proc_max = int(globalconfig["php-fpm"]["maxclients"])
        result = memory_estimate(proc_name)
        #print "php-fpm result: %r" % result
        if result:
            memory_print(result, proc_name, proc_max)

#globalconfig["nginx"]["maxclients"]

def MAGENTO_PRINT():
    pass
################################################
# Magento
################################################

print "\nMagento versions installed:"
if globalconfig.get("magento",{}).get("doc_root"):
    for key, value in globalconfig["magento"]["doc_root"].iteritems():
        print "%s %s" % (key,value["magento_version"])
pp.pprint(globalconfig["magento"]["doc_root"])
#print "1424: %r" % globalconfig["magento"]["doc_root"]
"""
m = magentoCtl()
filename="local.xml"
local_xml = m.open_local_xml(filename)
pp = pprint.PrettyPrinter(indent=4)
pp.pprint(local_xml)
"""







"""
{'domains':
    ['example.com', 'www.example.com new.example.com'],
    'config_file': '/etc/httpd/conf/httpd.conf',
    'doc_root': '/var/www/html',
    'listening': ['*:80']}
"""

"""
 _____ ___  ____   ___  
|_   _/ _ \|  _ \ / _ \ 
  | || | | | | | | | | |
  | || |_| | |_| | |_| |
  |_| \___/|____/ \___/ 
"""
class TODO():
    pass
"""
# these might be good ideas from Daniel, but the second doesn't work and is complicated. So I went back to simple.
globalconfig["doc_roots"] = set(one['doc_root'] for one in globalconfig.get("apache",{}).get("sites") if one.get('doc_root', None))
globalconfig["doc_roots"].update(one['doc_root'] for one in globalconfig.get("nginx",{}).get("sites") if one.get('doc_root', None))
"""
#print "1209 doc_roots %r" % globalconfig["doc_roots"]

#print "split %s" % head

#globalconfig["magento"]["doc_root"][doc_root_path]["Mage.php"] = mage_php_matches[0]
#globalconfig["magento"]["doc_root"][doc_root_path]["magento_path"] = head
#globalconfig["magento"]["doc_root"][doc_root_path]["magento_version"] = "Magento %s %s" % (mage["version"],mage["edition"])
#globalconfig["magento"]["doc_root"][doc_root_path]["mage_version"] = mage

# os.path.dirname(path)
#print "1249 %r" % globalconfig["magento"]["doc_root"]

#print "mage_php_matches:"


"""
#globalconfig["apache"]["sites"]["doc_root"]
if not "magento" in globalconfig:
    globalconfig["magento"] = {}
if not "doc_root" in globalconfig["magento"]:
    globalconfig["magento"]["doc_root"] = {}
    doc_root_path = globalconfig["apache"]["sites"]["doc_root"]
    globalconfig["magento"]["doc_root"][doc_root_path] = { "Mage.php" : "", "local.xml" : "", "magento_path" : "" }
#globalconfig["magento"]["doc_root"][doc_root_path]["Mage.php"] = ""
#globalconfig["magento"]["doc_root"][doc_root_path]["local.xml"] = ""
#globalconfig["magento"]["doc_root"][doc_root_path]["magento_path"] = ""
#globalconfig["magento"]["doc_root"][doc_root_path]["magento_version"] = ""
#globalconfig["magento"]["doc_root"][doc_root_path]["session_cache"] = ""
#globalconfig["magento"]["doc_root"][doc_root_path]["object_cache"] = ""
#globalconfig["magento"]["doc_root"][doc_root_path]["full_page_cache"] = ""
"""
# I will probably use the existance of those two files to assume a Magento install
# Mage.php provides version information
"""
magento = MagentoCtl()
mage = magento.version("Mage.php")
print "Magento %s %s" % (mage["version"],mage["edition"])
"""
# Save the config as a yaml file
filename = "config_dump.json"
if not os.path.isfile(filename):
    json_str=json.dumps(globalconfig)
    with open(filename,'w') as outfile:
        outfile.write( json_str )
    outfile.close()
"""
if os.path.isfile(filename):
    try:
        with open(filename,'r') as f:
            globalconfig=json.load(f)
    except:
        print "The file %s exists, but failed to import." % filename
else:
    print "The file %s does not exist." % filename
"""