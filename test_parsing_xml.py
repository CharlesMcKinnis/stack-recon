#!/usr/bin/env python2

import sys
import xml.etree.ElementTree as ET
import pprint

class magentoCtl(object):
    def open_local_xml(self, filename):
        print filename
        """
        provide the filename (absolute or relative) of local.xml
        
        returns: dict with db and cache information
        """
        try:
            tree = ET.ElementTree(filename)
        except:
            sys.exit(1)

        #tree = ET.ElementTree(file='local.xml')
        #tree = ET.ElementTree(file='local-memcache.xml')
        local_xml = {}
        
        section = "db"
        xml_parent_path = 'global/resources'
        xml_config_node = 'db/table_prefix'
        xml_config_section = 'default_setup/connection'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
        
        section = "session_cache"
        xml_parent_path = 'global'
        xml_config_node = 'session_save'
        xml_config_section = 'redis_session'
        xml_config_single = 'session_save_path'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section, xml_config_single = 'session_save_path'))
        
        section = "object_cache"
        xml_parent_path = 'global/cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section))
        
        section = "full_page_cache"
        xml_parent_path = 'global/full_page_cache'
        xml_config_node = 'backend'
        xml_config_section = 'backend_options'
        xml_config_single = 'slow_backend'
        local_xml.update(self.parse_local_xml(tree, section, xml_parent_path, xml_config_node, xml_config_section, xml_config_single = 'slow_backend'))
        
        return(local_xml)
    
    def parse_local_xml(self, tree, section, xml_parent_path, xml_config_node, xml_config_section, **kwargs):
        """
        provide:
            tree, ElementTree object
            section, string, name of section
            xml_parent_path, string, section of xml where information is
            xml_config_node, string, node name that describes the type
            xml_config_section, section of additional nodes and text contents
            xml_config_single, string of a single additional node under parent
    
        returns a dict with key named "section"
        """
        print tree, section, xml_parent_path, xml_config_node, xml_config_section
        local_xml = {}
        # full page cache (FPC) - redis
        #section = "full_page_cache"
        #print "\nsection: %s" % section
        #xml_parent_path = 'global/full_page_cache'
        #xml_config_node = 'backend'
        #xml_config_section = 'backend_options'
        if "xml_config_single" in kwargs:
            xml_config_single = kwargs["xml_config_single"]
        else:
            xml_config_single = ""
            
        if not section in local_xml:
            local_xml[section] = {}

        resources = tree.find(xml_parent_path)
        print resources
        if resources is not None:
            i = resources.find(xml_config_node)
        else:
            i = None
        if i is not None:
            #print "%s: %s" % (xml_config_node,i.text)
            local_xml[section][xml_config_node] = i.text
        # configuration
        if resources.find(xml_config_section) is not None:
            for i in resources.find(xml_config_section):
                #print "%s: %s" % (i.tag,i.text)
                local_xml[section][i.tag] = i.text
                
        if xml_config_single:
            if resources.find(xml_config_single) is not None:
                i = resources.find(xml_config_single)
                #print "%s: %s" % (i.tag,i.text)
                local_xml[section][i.tag] = i.text
        return local_xml
        pass

m = magentoCtl()
filename="local.xml"
local_xml = m.open_local_xml(filename)
pp = pprint.PrettyPrinter(indent=4)
pp.pprint(local_xml)


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
