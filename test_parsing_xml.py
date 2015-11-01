#!/usr/bin/env python2

import sys
import xml.etree.ElementTree as ET

tree = ET.ElementTree(file='local.xml')

def unroll(tree):
    for elem in tree.getiterator():
        print "9 %r %r" % (elem.tag, elem.attrib)
        for child in elem.getchildren():
            print "11 %r" % child.tag
            print "12 %r" % child.attrib
            print "13 %r" % child.text
root = tree.getroot()
for children in root:
    print "17 %s %s" % (children.tag,children.text)
    for child in children:
        print "19 %s %s" % (child.tag,child.text)
    

resources = tree.find('global/resources')
#resources = root.find('config')
print resources
print "Table prefix: %s" % resources.find('db/table_prefix').text
for i in resources.find('default_setup/connection'):
    print "%s: %s" % (i.tag,i.text)
    pass

"""
config/global/resources/
    db/table_prefix     text
    default_setup/connection
        host     text
        username     text
        password     text
        dbname     text
        initStatements     text
        model     text
        type     text
        active     text
        persistent     text
"""
"""
# redit sessions
config/global
    session_save     text
    redis_session
        host     text
        port     text
        password     text
        timeout     text
        persistent     text
        db     text
        compression_threshold     text
        compression_lib     text
        log_level     text
        max_concurrency     text
        break_after_frontend     text
        break_after_adminthml     text
        bot_lifetime     text
"""
"""
#redis objects
config/global
    cache
        backend     text
        backend_options
            server     text
            port     text
            persistent
            database
            password
            force_standalone
            connect_retries
            read_timeout
            automatice_cleaning_factor
            compress_data
            compress_tags
            compress_threshold
            compression_lib
"""
"""
#redis FPC
config/global
    full_page_cache
        backend
        slow_backend
        backend_options
            server
            port
            persistent
            database
            force_standalone
            connect_retries
            read_timeout
            automatice_cleaning_factor
            compress_data
            compress_tags
            compress_threshold
            compression_lib
            
"""
#print root.tag, root.attrib
# .iter doesn't exist in python 2.6 for RHEL 6
#for elem in tree.getiterator('config'):
#    print elem.tag, elem.attrib
#for child_of_root in root:
#    print child_of_root.tag, child_of_root.attrib
#print tree
#unroll(tree)
