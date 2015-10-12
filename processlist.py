#!/usr/bin/env python2

import re
import os

def processlist(var_filter=""):
    """
    var_filter = "text to search with"
    using this as the filter will find an executable by name whether it was call by absolute path or bare
    "^(\S*/bash|bash)"
    """
    processlist = {}
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    
    for pid in pids:
        try:
            pscmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read().replace("\000"," ").rstrip()
        except IOError: # proc has already terminated
            continue
        if pscmd:
            if var_filter:
                ps_filter = re.search(var_filter,pscmd)
                if ps_filter:
                    processlist[pid] = pscmd
            else:
                processlist[pid] = pscmd
    return(processlist)

# works
#pslist = processlist("^(\S*/bash|bash)")
#for key in pslist.keys():
#    print "%6d %s" % (int(key),pslist[key])

# also works
#for key, value in processlist("^(\S*/bash|bash)").iteritems():
#    print "%6d %s" % (int(key),value)
    
# works, no filter
#for key, value in processlist().iteritems():
#    print "%6d %s" % (int(key),value)

import psutil
#print psutil.version_info

class AutoVivification(dict):
    """Implementation of perl's autovivification feature."""
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value

var_filter = "http"

daemons = {}

pidlist = psutil.get_pid_list()
for pid in pidlist:
    p = psutil.Process(pid)
    if p.exe:
        #ps_filter = re.search(var_filter,p.exe)
        #print os.path.basename(p.exe)
        match_exe = ["httpd", "apache2", "nginx"]
        for daemon_name in match_exe:
            if os.path.basename(p.exe) == daemon_name:
                #if ps_filter:
                if not "daemon_name" in daemons:
                    daemons[daemon_name] = {}
                if not "exe" in daemons[daemon_name]:
                    daemons[daemon_name]["exe"] = []
                daemons[daemon_name]["exe"] += [p.exe]
                print p.exe

for key,value in daemons.iteritems():
    print "%s %r" % (key,value)