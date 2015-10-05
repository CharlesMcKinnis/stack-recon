#!/usr/bin/env python2
import re

var_onefile = "./amalg.conf"
var_count = 0

infile = open(var_onefile, 'r')

var_wholeconfig = infile.readlines()

for line in var_wholeconfig:
    print(line.rstrip())
    var_count+=len(re.findall('{',line))
    var_count-=len(re.findall('}',line))
    print var_count
    #pattern = compile(r'{')
    #iterator = finditer(pattern, line)
    #for match in iterator:
    #    count += 1
    #print count

