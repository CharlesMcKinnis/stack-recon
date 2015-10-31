#!/usr/bin/env python2

import xml.etree.ElementTree as ET

tree = ET.ElementTree(file='local.xml')

def unroll(tree):
    for elem in tree.getiterator():
        print elem.tag, elem.attrib
        #print type(elem)
        for child in elem.getchildren():
            print child.tag
    else:
        exit(0)
root = tree.getroot()
#print root.tag, root.attrib
# .iter doesn't exist in python 2.6 for RHEL 6
#for elem in tree.getiterator('config'):
#    print elem.tag, elem.attrib
#for child_of_root in root:
#    print child_of_root.tag, child_of_root.attrib
#print tree
unroll(tree)
