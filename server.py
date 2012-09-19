#!/usr/bin/env python
###
# Simple python API server for honeypot stats
#
# Copyright (c) 2012 by ManiacTwister
#
###
# GNU General Public Licence (GPL)
# 
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
###
 
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
 
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
 
    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message
 
import socket
 
allowedhost = '176.9.44.144'
#allowedhost = '81.217.14.212'
host = ''
port = 13342
backlog = 5
size = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((host,port))
s.listen(backlog)
while 1:
	client, address = s.accept()
	cfile = client.makefile('rw',0)
	data = client.recv(size)
	if data and address[0] == allowedhost:
		request = HTTPRequest(data)
		if request.path == '/stats':
			f = open("/root/stats.json", "r")
			try:
				string = f.read()
			finally:
				f.close()
			cfile.write('HTTP/1.0 200 OK\r\n')
			cfile.write("Content-Type: text/plain\r\n\r\n")
			cfile.write(string)
		elif request.path == '/':
			cfile.write('HTTP/1.0 200 OK\r\n')
			cfile.write("Content-Type: text/html\r\n\r\n")
			cfile.write('<html><body><h1>/</body></html>')
		else:
			cfile.write('HTTP/1.0 200 OK\r\n')
			cfile.write("Content-Type: text/html\r\n\r\n")
			cfile.write('<html><body><h1>'+request.path+'</body></html>')
    	cfile.close()
	client.close()
