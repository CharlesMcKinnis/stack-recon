#!/usr/bin/env python2

import xml.etree.ElementTree as ET
    
tree = ET.ElementTree(file='local.xml')

root = tree.getroot()
print root.tag, root.attrib
for elem in tree.iter():
    print elem.tag, elem.attrib
    