#!/usr/bin/env python2

import xml.etree.ElementTree
    
tree = xml.etree.ElementTree(file='local.xml')

root = tree.getroot()
print root.tag, root.attrib
