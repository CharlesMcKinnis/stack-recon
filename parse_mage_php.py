#!/usr/bin/env python2
import re

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

onefile_handle = open(onefile, 'r')
for line in onefile_handle:
    result = re.match("static\s+private\s+$_currentEdition\s*=\s*self::([^\s;]+);", line.strip(), re.IGNORECASE )
    if result:
        print result.group(1)
    #result = re.match("public static function getVersionInfo\(\)", line.strip(), re.IGNORECASE)
    if "public static function getVersionInfo()" in line:
        print "yep, %s" % line

        

