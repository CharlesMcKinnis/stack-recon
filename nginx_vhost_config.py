#!/usr/bin/env python2

import re
import glob
import subprocess
import sys

conffile = "./etc/nginx/nginx.conf"

class apache:
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

class nginxCtl:

    """
    A class for nginxCtl functionalities
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
            sys.exit(1)

    def get_nginx_lock(self):
        """
        :returns: nginx lock file location which is required for nginx services
        """

        try:
            return self.get_conf_parameters()['--lock-path']
        except:
            #print "nginx is not installed!!!"
            sys.exit(1)

class AutoVivification(dict):
    """Implementation of perl's autovivification feature."""
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value

def importfile(filename, keyword_regex):
    """
    pass the filename of the base config file, and a keyword regular expression to identify the include directive.
    The regexp should include parantheses ( ) around the filename part of the match
    
    Examples (the regexp is case insensitive):
    nginx
        wholeconfig = importfile(conffile,'\s*include\s+(\S+);')
    httpd
        wholeconfig = importfile(conffile,'\s*include\s+(\S+);')
    """
    files = glob.iglob(filename)
    combined = ""

    for onefile in files:
        #infile = open(filename, 'r')
        try:
            infile = open(onefile, 'r')
        except:
            return()

        for line in infile:
            #print "%s" % line.rstrip()
            #print "%s" % line.strip() # removes whitespace on left and right
            result = re.match(keyword_regex, line.strip(), re.IGNORECASE )
            #result = re.match('(include.*)', line.strip(), re.I | re.U )
            if result:
                combined += "#"+line+"\n"
                #print "#include %s " % result.group(1)
                combined += importfile(result.group(1),keyword_regex)
            else:
                combined += line
                #print line.rstrip()
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
wholeconfig = importfile(nginx_conf_path,'\s*include\s+(\S+);')
if wholeconfig:
    nginx_stanzas = parse_nginx_config(wholeconfig)
    for one in sorted(nginx_stanzas.keys(),key=int):
        print "%s %s" % (one,nginx_stanzas[one])
