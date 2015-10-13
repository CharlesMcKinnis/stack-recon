#!/usr/bin/env python2
import subprocess
import re

class ansi:
    """
    This class is to display different color fonts
    example:
    print "Testing a color    [ %sOK%s ]" % (
        ansi.CYAN,
        ansi.ENDC
                    )
    or to avoid a new line
    import sys
    sys.stdout.write("%s%s" % (ansi.CLR,ansi.HOME))
    """
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CLR = '\033[2J'
    HOME = '\033[H'

def estiMate(count, process_name, **kwargs):
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
    #print "free_mem: %d line_count: %d line_sum: %d biggest: %d" % (free_mem,line_count,line_sum,biggest)
    #output = re.sub('configure arguments:', '', output)
    #dict = {}
    #for item in output.split(" "):
    #    if len(item.split("=")) == 2:
    #        dict[item.split("=")[0]] = item.split("=")[1]
    #return dict

proc_max = 10
proc_name = "sh"
result = estiMate(proc_max, proc_name, display=True)
#for i in result:
#    print i, result[i]

print "%d %s processes are currently using %d KB of memory." % (result["line_count"], proc_name, result["line_sum"])
print "Average memory per process: %d KB will use %d KB if max clients %d is reached." % (
    result["line_sum"]/result["line_count"], int(result["line_sum"]/result["line_count"]*proc_max), proc_max
    )
print "Largest process: %d KB will use %d KB if MaxClients is reached.\n" % (
    result["biggest"], result["biggest"]*proc_max
    )
print "Based on the largest process, use this as a health check: %d" % (int(
    (result["free_mem"]+result["line_sum"]) - (result["biggest"]*proc_max) / result["biggest"]
    ))
# red if proc_max > int( (result["line_sum"]+result["free_mem"]) / result["biggest"] )
# green elif proc_max <= int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
# yellow else
print "Positive numbers may mean you can have more clients. Negative numbers mean you are overcommited."
print "See below for numbers advice.\n"
print "How many max clients you may be able to handle based on the average size? %d" % (
    int(( (result["line_sum"]+result["free_mem"]) / (result["line_sum"]/result["line_count"]) )*.8)
    )
print "How many max clients you can handle based on largest process and 100%% commit? %d" % int( (result["line_sum"]+result["free_mem"]) / result["biggest"] )

print "How many max clients you can safely handle based on largest process and 80%% commit? %d" % int( (result["line_sum"]+result["free_mem"]) / result["biggest"] * .8)
