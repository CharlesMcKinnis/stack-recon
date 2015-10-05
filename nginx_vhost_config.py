#!/usr/bin/env python2
import re
import glob

conffile = "./amalg.conf"
stanza_count = 0
server_start = 0

def importfile(filename, keyword):

    files = glob.iglob(filename)
    combined = ""

    for onefile in files:
        #infile = open(filename, 'r')
        infile = open(onefile, 'r')

        for line in infile:
            #print "%s" % line.rstrip()
            #print "%s" % line.strip() # removes whitespace on left and right
            result = re.match('\s*%s\s+(\S+);' % keyword, line.strip() )
            #result = re.match('(include.*)', line.strip(), re.I | re.U )
            if result:
                combined += "#"+line+"\n"
                #print "#include %s " % result.group(1)
                combined += importfile(result.group(1),keyword)
            else:
                combined += line
                #print line.rstrip()
    return combined

#infile = open(onefile, 'r')

#wholeconfig = infile.readlines()
wholeconfig = importfile(conffile,"include")
#print wholeconfig

for line in wholeconfig.splitlines():
    #print(line.rstrip())
    # this doesn't do well if you open and close a stanza on the same line
    if len(re.findall('{',line)) > 0 and len(re.findall('}',line)) > 0:
        print "This script does not consistently support opening and closing stanzas on the same line."
    stanza_count+=len(re.findall('{',line))
    stanza_count-=len(re.findall('}',line))
    #print "%d - %d" % (stanza_count,server_start)
    result = re.match('^\s*server', line.strip() )
    if result:
        server_start = stanza_count
    # are we in a server block, and not a child stanza of the server block? is so, look for keywords
    # this is so we don't print the root directive for location as an example. That might be useful, but isn't implemented at this time.
    if server_start == stanza_count:
        # we are in a server block
        #result = re.match('\s*(listen|server|root)', line.strip())
        result = re.match('\s*(listen|server_name|root)', line.strip())
        if result:
            print line.strip()
    # if the server block is bigger than the current stanza, we have left the server stanza we were in
    if server_start > stanza_count and server_start > 0:
        # we are no longer in the server { block
        server_start = 0
        print ""
