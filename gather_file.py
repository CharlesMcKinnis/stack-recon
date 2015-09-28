#!/usr/bin/env python2

import re
import glob

def importfile(var_filename, var_keyword):

    var_files = glob.iglob(var_filename)
    var_combined = ""

    for var_onefile in var_files:
        #infile = open(var_filename, 'r')
        infile = open(var_onefile, 'r')

        for line in infile:
            #print "%s" % line.rstrip()
            #print "%s" % line.strip() # removes whitespace on left and right
            var_result = re.match('\s*%s\s+(\S+);' % var_keyword, line.strip() )
            #var_result = re.match('(include.*)', line.strip(), re.I | re.U )
            if var_result:
                var_combined += "#"+line+"\n"
                #print "#include %s " % var_result.group(1)
                var_combined += importfile(var_result.group(1),var_keyword)
            else:
                var_combined += line
                #print line.rstrip()
    return var_combined

print importfile("etc/nginx/nginx.conf","include")
