#!/usr/bin/env python2
import re

var_onefile = "./amalg.conf"
var_count = 0
var_server_start = 0

infile = open(var_onefile, 'r')

var_wholeconfig = infile.readlines()

for line in var_wholeconfig:
    #print(line.rstrip())
    var_count+=len(re.findall('{',line))
    var_count-=len(re.findall('}',line))
    #print var_count
    var_result = re.match('^\s*server', line.strip() )
    if var_result:
        var_server_start = var_count
    if var_server_start > 0:
        # we are in a server block
        #var_result = re.match('\s*(listen|server|root)', line.strip())
        var_result = re.match('\s*(listen|server_name|root)', line.strip())
        if var_result:
            print line.strip()
    if var_server_start < var_count and var_server_start > 0:
        # we are no longer in the server { block
        var_server_start=0
        print ""
        

    #pattern = compile(r'{')
    #iterator = finditer(pattern, line)
    #for match in iterator:
    #    count += 1
    #print count            if var_result:


