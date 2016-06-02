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
STACK_STATUS_VERSION = 2016051601

from ecommstacklib import *
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
    parser.add_argument("--nomagento", help="Skip Magento detection; it will detect apache, nginx and php-fpm for normal L?MP stacks",
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
    args.nomagento = None
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
    sys.stderr.write("apache data gather\n")
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
            wholeconfig = importfile(apache_conf_file, '\s*include(?:optional?)?\s+[\'"]?([^\s\'"]+)[\'"]?', base_path = apache_root_path)
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
                'domains': ['domain.com', 'www.domain.com new.domain.com'],
                'config_file': '/etc/httpd/conf.d/ssl.conf',
                'doc_root': '/var/www/html',
                'listening': ['192.168.100.248:443']
                }, {
                'domains': ['wilshirewigs.com', 'www.domain.com new.domain.com'],
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
    sys.stderr.write("nginx data gather\n")
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
    sys.stderr.write("php-fpm data gather\n")
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
    
    if not args.nomagento:
        def MAGENTO_DATA_GATHER():
            pass
        sys.stderr.write("magento data gather\n")
        ################################################
        # Magento
        ################################################
        # get a list of unique document roots
        doc_roots = set()
        # sys.stderr.write("2010\n")
        if globalconfig.get("apache",{}).get("sites"):
            for one in globalconfig["apache"]["sites"]:
                if "doc_root" in one:
                    doc_roots.add(one["doc_root"])
        # sys.stderr.write("2015\n")
        if globalconfig.get("nginx",{}).get("sites"):
            for one in globalconfig["nginx"]["sites"]:
                if "doc_root" in one:
                    doc_roots.add(one["doc_root"])
        #if not "doc_roots" in globalconfig:
        #    globalconfig["doc_roots"] = set()
        # sys.stderr.write("2033\n")
        globalconfig["doc_roots"] = list(doc_roots)
        
        # magento = MagentoCtl()
        # sys.stderr.write("2026\n")
        if not "magento" in globalconfig:
            globalconfig["magento"] = {}
        # find mage.php files in document roots
        # try:
        # sys.stderr.write("2031\n")
        if True:
            mage_files = magento.find_mage_php(globalconfig["doc_roots"])
        # except:
        #     sys.stderr.write("No Magento found in the web document roots\n")
        # get Magento information from those Mage.php
        # sys.stderr.write("2037\n")
        mage_file_info = magento.mage_file_info(mage_files)
        # sys.stderr.write("2039\n")
        globalconfig["magento"]["doc_root"] = mage_file_info
        
        
        # returns a dict
        # return_dict[doc_root_path]["Mage.php"] = mage_php_match
        # return_dict[doc_root_path]["magento_path"] = head
        # return_dict[doc_root_path]["local_xml"] = { }
        # return_dict[doc_root_path]["local_xml"]["filename"] = os.path.join(head, "app", "etc", "local.xml")
        # return_dict[doc_root_path]["magento_version"] = "%s" % mage["version"]
        mage_file_info = magento.mage_file_info(mage_files)
        globalconfig["magento"]["doc_root"] = mage_file_info
        
        for doc_root in globalconfig["magento"]["doc_root"]:
            # sys.stderr.write("2054\n")
            if not doc_root in globalconfig["magento"]["doc_root"]:
                globalconfig["magento"]["doc_root"][doc_root] = {}
            # else:
            #     print 'DEFINED: %s in globalconfig["magento"]["doc_root"]' % doc_root
            #     print type(globalconfig["magento"]["doc_root"][doc_root])
            # sys.stderr.write("2060\n")
            
            # 1-20-2016 this is not a safe assumption, fixed
            #local_xml = os.path.join(doc_root,"app","etc","local.xml")
            local_xml = globalconfig["magento"]["doc_root"][doc_root]["local_xml"]["filename"]
            
            # if local_xml doesn't exist, then mage_file_info above failed.
            if not "local_xml" in globalconfig["magento"]["doc_root"][doc_root]:
                globalconfig["magento"]["doc_root"][doc_root]["local_xml"] = { }
            # else:
            
            # 1-20-2016 fixed
            update(globalconfig["magento"]["doc_root"][doc_root]["local_xml"], magento.open_local_xml(doc_root,globalconfig["magento"]["doc_root"][doc_root]))

            # redis_module_xml = os.path.join(docroot,"app","etc","modules","Cm_RedisSession.xml")
            # app/etc/modules/Cm_RedisSession.xml
            # globalconfig["magento"]["doc_root"][doc_root]["local_xml"]
            # sys.stderr.write("2076\n")
            
            # get the cache table information, and store it in ["magento"]["doc_root"][doc_root]["cache"]["cache_option_table"]
            update(globalconfig["magento"]["doc_root"][doc_root],
                magento.db_cache_table(doc_root,
                    globalconfig["magento"]["doc_root"][doc_root].get("local_xml",{}).get("db",{})
                )
            )
            # print "2078 globalconfig"
            # pp.pprint(globalconfig)
            #if return_config:
            #    #globalconfig["magento"]["doc_root"][doc_root]["cache"]["cache_option_table"]
            #    globalconfig["magento"]["doc_root"].update(return_config)
    
        def MEMCACHE_DATA_GATHER():
            pass
        sys.stderr.write("memcache data gather\n")
        # memcache = MemcacheCtl()
        
        memcache_instances = memcache.instances(globalconfig.get("magento",{}).get("doc_root",{}))
    
        if not globalconfig.get("memcache") and memcache_instances:
            globalconfig["memcache"] = {}
        if memcache_instances:
            update(globalconfig["memcache"], memcache.get_all_statuses(memcache_instances))
    
    
        def REDIS_DATA_GATHER():
            pass
        sys.stderr.write("redis data gather\n")
        # redis = RedisCtl()
        # print "2101"
        redis_instances = redis.instances(globalconfig.get("magento",{}).get("doc_root",{}))
        #pp.pprint(redis_instances)
        # print "1984 redis_instances"
        # pp.pprint(redis_instances)
        # print "2106"
        if not globalconfig.get("redis") and redis_instances:
            globalconfig["redis"] = {}
        # print "2109"
        if redis_instances:
            # print "2111"
            #fixme add redis password
            update(globalconfig["redis"], redis.get_all_statuses(redis_instances))
            # print "2114"

    def MYSQL_DATA_GATHER():
            pass
    sys.stderr.write("mysql data gather\n")
    ################################################
    # MySQL
    ################################################
    
    if not "mysql" in globalconfig:
        globalconfig["mysql"] = {}
    #globalconfig["mysql"] = mysql_config
    
    # find mysql from local_xml
    """
    I want to add globalconfig["mysql"], and I'll need a list of them I guess?
    Each one needs host and auth info
    Then a dict for each query that contains a dict of key value pairs

    dbConnInfo = globalconfig["magento"]["doc_root"][doc_root]["local_xml"]["db"]
    output = db_query(dbConnInfo, sqlquery)
    parse_key_value(output)
    
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
else:
    # print "2114"
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
# sys.stderr.write("nginx data print\n")
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
# sys.stderr.write("apache data print\n")
################################################
# APACHE
################################################
if "apache" in  globalconfig:
    apache.figlet()
    if globalconfig.get("apache",{}).get("version"):
        print "Apache version: %s" % globalconfig.get("apache",{}).get("version")
    else:
        print "No apache version?"
    if globalconfig.get("apache",{}).get("daemon",{}).get("Server MPM"):
        print "Apache server MPM: %s\n" % globalconfig.get("apache",{}).get("daemon",{}).get("Server MPM")
    else:
        print "No apache server MPM?\n"
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
# sys.stderr.write("php-fpm data print\n")
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
# sys.stderr.write("magento data print\n")
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
            # THIS WAS WRONG
            # print "local.xml: %s" % os.path.join(key,"app","etc","local.xml")
            print "local.xml: %s" % value["local_xml"]["filename"]
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
# sys.stderr.write("memcache data print\n")
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
# sys.stderr.write("redis data print\n")
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
