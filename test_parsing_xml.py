#!/usr/bin/env python2

import xml.etree.ElementTree as ET
    
tree = ET.ElementTree(file='local.xml')

root = tree.getroot()
#print root.tag, root.attrib
# .iter doesn't exist in python 2.6 on RHEL 6
#for elem in tree.iter():
#    print elem.tag, elem.attrib
for child_of_root in root:
    print child_of_root.tag, child_of_root.attr