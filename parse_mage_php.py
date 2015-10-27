#!/usr/bin/env python2
import re
import os
docroot = "/data/sites/purlsoho.com/live"
onefile = os.path.join(docroot, "app", "Mage.php")
onefile = "Mage.php"
"""
grep Mage.php
/static\s+private\s+$_currentEdition\s*=\s*self::([^\s;]+);/
    static private $_currentEdition = self::EDITION_ENTERPRISE;


    public static function getVersionInfo()
    {
        return array(
            'major'     => '1',
            'minor'     => '14',
            'revision'  => '1',
            'patch'     => '0',
            'stability' => '',
            'number'    => '',
        );
    }
"""
class MagentoCtl(object):
    
    def version(self, mage_php_file):
        mage = {}
        file_handle = open(mage_php_file, 'r')
        for line in file_handle:
            result = re.match("static\s+private\s+\$_currentEdition\s*=\s*self::([^\s;]+);", line.strip(), re.IGNORECASE )
            if result:
                mage["edition"] = result.group(1)
            #result = re.match("public static function getVersionInfo\(\)", line.strip(), re.IGNORECASE)
            if "public static function getVersionInfo()" in line:
                line = file_handle.next() # {
                line = file_handle.next() # return array(
                while not ");" in line:
                    line = file_handle.next()
                    result = re.match("'([^']+)'\s*=>\s*'([^']*)'", line.strip())
                    if result:
                        mage[result.group(1)] = result.group(2)
                break
        file_handle.close()
        # join them with periods, unless they are empty, then omit them
        mage["version"] = ".".join(filter(None,[mage["major"],mage["minor"],mage["revision"],mage["patch"],mage["stability"],mage["number"]]))
        return(mage)
    
    def localxml(self, local_xml_file):
        pass

magento = MagentoCtl()
mage = magento.version("Mage.php")
print "Magento %s %s" % (mage["version"],mage["edition"])

