#!/usr/bin/env python2

import re
import glob
import subprocess
import sys
import os

conffile = "etc/nginx/nginx.conf"
conffile = "etc/nginx/nginx.conf"

class apacheCtl:
    """
    [root@527387-db1 26594]# httpd -V
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
        """
        Finds configuration parameters

        :returns: list of configuration parameters
        Server version - Apache/2.2.15 (Unix)
        Server built - Aug 18 2015 02:00:22
        Server's Module Magic Number - 20051115:25
        Server loaded - APR 1.3.9, APR-Util 1.3.9
        Compiled using - APR 1.3.9, APR-Util 1.3.9
        Architecture - 64-bit
        Server MPM - Prefork
        threaded - no
        forked - yes (variable process count)

        APACHE_MPM_DIR - server/mpm/prefork
        APR_HAS_SENDFILE - 
        APR_HAS_MMAP - 
        APR_HAVE_IPV6 (IPv4-mapped addresses enabled) - 
        APR_USE_SYSVSEM_SERIALIZE - 
        APR_USE_PTHREAD_SERIALIZE - 
        SINGLE_LISTEN_UNSERIALIZED_ACCEPT - 
        APR_HAS_OTHER_CHILD - 
        AP_HAVE_RELIABLE_PIPED_LOGS - 
        DYNAMIC_MODULE_LIMIT - 128
        HTTPD_ROOT - /etc/httpd
        SUEXEC_BIN - /usr/sbin/suexec
        DEFAULT_PIDLOG - run/httpd.pid
        DEFAULT_SCOREBOARD - logs/apache_runtime_status
        DEFAULT_LOCKFILE - logs/accept.lock
        DEFAULT_ERRORLOG - logs/error_log
        AP_TYPES_CONFIG_FILE - conf/mime.types
        SERVER_CONFIG_FILE - conf/httpd.conf
        """
        conf = "httpd -V 2>&1"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
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
            return()

    def get_conf(self):
        """
        :returns: configuration path location
        HTTPD_ROOT/SERVER_CONFIG_FILE
        """
        try:
            return os.path.join(self.get_conf_parameters()['HTTPD_ROOT'],self.get_conf_parameters()['SERVER_CONFIG_FILE'])
        except KeyError:
            #print " is not installed!!!"
            return()

class nginxCtl:

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
        version = "nginx -v"
        p = subprocess.Popen(
            version, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
            )
        output, err = p.communicate()
        return err

    def get_conf_parameters(self):
        """
        Finds nginx configuration parameters

        :returns: list of nginx configuration parameters
        """
        conf = "nginx -V 2>&1 | grep 'configure arguments:'"
        p = subprocess.Popen(
            conf, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        output = re.sub('configure arguments:', '', output)
        dict = {}
        for item in output.split(" "):
            if len(item.split("=")) == 2:
                dict[item.split("=")[0]] = item.split("=")[1]
        return dict

    def get_nginx_conf(self):
        """
        :returns: nginx configuration path location
        """
        try:
            return self.get_conf_parameters()['--conf-path']
        except KeyError:
            #print "nginx is not installed!!!"
            sys.exit(1)

    def get_nginx_bin(self):
        """
        :returns: nginx binary location
        """
        try:
            return self.get_conf_parameters()['--sbin-path']
        except:
            #print "nginx is not installed!!!"
            sys.exit(1)

    def get_nginx_pid(self):
        """
        :returns: nginx pid location which is required by nginx services
        """

        try:
            return self.get_conf_parameters()['--pid-path']
        except:
            #print "nginx is not installed!!!"
            return()

    def get_nginx_lock(self):
        """
        :returns: nginx lock file location which is required for nginx services
        """

        try:
            return self.get_conf_parameters()['--lock-path']
        except:
            #print "nginx is not installed!!!"
            return()

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
    def full_file_path(right_file):
        # If the right side of the full name doesn't have a leading slash, it is a relative path.
        #     Add the base_path to the left and return the value
        # else just return the name
        if right_file[0] not in "/":
            return(base_path+"/"+right_file)
        else:
            return(filename)
    print "full path to file: %s" % full_file_path(filename)
    files = glob.iglob( full_file_path(filename) ) # either an absolute path to a file, or absolute path to a glob
    #print "%r" % files
    combined = ""

    for onefile in files:
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
                nestedfile = full_file_path(result.group(1))
                combined += importfile(nestedfile, keyword_regex, **kwargs)
            else:
                combined += line
        # END of the file import, if it was a file and not a glob, make the ending. onefile should always be a file
        if os.path.isfile(onefile):
            #print "END onefile: %s" % onefile
            combined += "## END "+onefile+"\n"
    return combined


def parse_nginx_config(wholeconfig):
    """
    list structure
    [ server stanza { line : { listen: [ ], server_name : [ ], root { location : path } } } ]
    """
    stanza_count = 0
    server_start = 0
    location_start = 0
    linenum = 0
    nginx_stanzas = {} #AutoVivification()
    for line in wholeconfig.splitlines():
        linenum += 1
        # this doesn't do well if you open and close a stanza on the same line
        if len(re.findall('{',line)) > 0 and len(re.findall('}',line)) > 0:
            print "This script does not consistently support opening { and closing } stanzas on the same line."
        stanza_count+=len(re.findall('{',line))
        stanza_count-=len(re.findall('}',line))
        result = re.match('^\s*server\s', line.strip() )
        if result:
            server_start = stanza_count
            server_line = str(linenum)
            if not server_line in nginx_stanzas:
                nginx_stanzas[server_line] = { }
        # are we in a server block, and not a child stanza of the server block? is so, look for keywords
        # this is so we don't print the root directive for location as an example. That might be useful, but isn't implemented at this time.
        if server_start == stanza_count:
            # we are in a server block
            #result = re.match('\s*(listen|server|root)', line.strip())
            result = re.match('\s*(listen|server_name|root)\s*(.*)', line.strip("\s\t;"))
            if result:
                #print line.strip()
                if result.group(1)=="listen":
                    if not result.group(1) in nginx_stanzas[server_line]:
                        nginx_stanzas[server_line][result.group(1)] = []
                    nginx_stanzas[server_line][result.group(1)] += [result.group(2)]
                    #print "listen %s" % result.group(2)
                if result.group(1)=="access_log":
                    if not result.group(1) in nginx_stanzas[server_line]:
                        nginx_stanzas[server_line][result.group(1)] = []
                    nginx_stanzas[server_line][result.group(1)] += [result.group(2)]
                    #print "listen %s" % result.group(2)
                if result.group(1)=="error_log":
                    if not result.group(1) in nginx_stanzas[server_line]:
                        nginx_stanzas[server_line][result.group(1)] = []
                    nginx_stanzas[server_line][result.group(1)] += [result.group(2)]
                    #print "listen %s" % result.group(2)
                if result.group(1)=="server_name":
                    if not result.group(1) in nginx_stanzas[server_line]:
                        nginx_stanzas[server_line][result.group(1)] = []
                    nginx_stanzas[server_line][result.group(1)] += result.group(2).split()
                    #print "server_name %s" % result.group(2)
                if result.group(1)=="root":
                    #if not result.group(1) in nginx_stanzas[server_line]:
                    #    nginx_stanzas[server_line][result.group(1)] = {}
                    nginx_stanzas[server_line][result.group(1)] = result.group(2)
                    #print "root %s" % result.group(2)
        # if the server block is bigger than the current stanza, we have left the server stanza we were in
        # if server_start > stanza_count and server_start > 0: # The lowest stanza_count goes is 0, so it is redundant
        if server_start > stanza_count:
            # we are no longer in the server { block
            server_start = 0
            #print ""
    return nginx_stanzas

def parse_apache_config(wholeconfig):
    """
    <VirtualHost *:80>
    DocumentRoot /var/www/vhosts/example.com/httpdocs
    ServerName example.com
    ServerAlias www.example.com
    <Directory /var/www/vhosts/example.com/httpdocs>
    </Directory>
    CustomLog /var/log/httpd/example.com-access_log combined
    ErrorLog /var/log/httpd/example.com-error_log
    </VirtualHost>
    """

"""
need to check directory permissions
[root@localhost vhosts]# ll
total 4
drwxrwxr-x 3 user user 4096 Sep 15 17:11 example.com
"""

n = nginxCtl()
try:
    nginx_conf_path = n.get_nginx_conf()
except:
    print "nginx is not installed"
    nginx_conf_path = conffile
print "Using config %s" % nginx_conf_path
#nginx
#wholeconfig = importfile(nginx_conf_path,'\s*include\s+(\S+);',base_path="/home/charles/Documents/Rackspace/ecommstatustuning/")

a = apacheCtl()
apache_conf_path = a.get_conf()
print apache_conf_path
#exit(0)
#apache_conf_path = "conf/httpd.conf"
#apache
wholeconfig = importfile(apache_conf_path,'\s*include\s+(\S+)',base_path="/home/charles/Documents/Rackspace/ecommstatustuning/etc/httpd")
if wholeconfig:
    #nginx_stanzas = parse_nginx_config(wholeconfig)
    #for one in sorted(nginx_stanzas.keys(),key=int):
        #print "%s %s" % (one,nginx_stanzas[one])
    print wholeconfig

#apacheCtl.get_conf_parameters()
