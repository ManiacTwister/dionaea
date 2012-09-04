#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* 
#*             contact nepenthesdev@gmail.com  
#*
#*******************************************************************************/

from dionaea.core import connection, ihandler, g_dionaea, incident
from io import open
import base64
import hashlib
import re
import random
import mmap
import json
import hashlib
import tempfile
import logging
from random import choice
import string
import copy

logger = logging.getLogger('logirc')
logger.setLevel(logging.INFO)


def HH(some): return hashlib.md5(some).hexdigest()
def H(some): return hashlib.md5(some).digest()


''' IRC Client begin '''

class ircclient:
    commandhash = {"/list":"LIST", "/join":"JOIN", "/nick":"NICK"}
    openchannels = []
    channel = None
    ## This constructor does the housekeeping presumed for any irc connection and represents
    ## a single server. As of now this program only supports connection to one server at a time
    ## (and in fact, one channel as well) but this will be addressed in future versions.
    def __init__(self, address, port=6667, realname, ident, nick, password, channel):
        self.address = address # record the server address for future use
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # set up the socket
 
        ## Get identity information needed by the server.
        self.realname = realname
        self.ident = ident
        self.nick = nick
        self.channel = channel
        self.state = 'offline'
 

    def connect():
        self.sock.connect((socket.gethostbyname(address), port)) # connect to the server
        self.sock.send("USER %s %s %s :%s\r\n" % (self.ident, address, "UNIX-SERVER", self.realname)) # send identity stuff
        self.sock.send("NICK %s\r\n" % self.nick) # tell the server our desired nick
        self.sock.send("JOIN %s\r\n" % self.channel) # join channel
        self.state = 'online'
    def parseMessage(self, message):
        nick = message[message.index(":"):message.index("!")]
        message = message[message.index(":") + 1:]
        message = message[message.index(":"):]
        return "%s %s" % (nick, message)
    def server_response(self):
        response = self.sock.recv(1024)
        if "!" in response and ":" in response[response.index(":") + 1:]:
            return self.parseMessage(response)
        if "PING :" in response:
            self.sock.send(response.replace("PING", "PONG"))
            return 0
        return response
    def send_message(self, message):
        if not message:
            return False
        '''for i in self.commandhash:
            if message[:len(i)] == i:
                message = message.split(" ")
                if len(message) == 2:
                    if message[0] == "/join":
                        self.channel = message[1]
                    return self.sock.send(self.commandhash[i] + " " + message[1] + "\r\n")
                return self.sock.send(self.commandhash[i] + "\r\n")'''
        if self.channel:
            message_tuple = (self.nick, self.ident, self.address, self.channel, message)
            return self.sock.send(":%s!%s@%s PRIVMSG %s :%s\r\n" % message_tuple)
        else:
            print "No channel selected"
            return False
    def close(self):
        self.sock.close()
        return

''' IRC Client end '''

class logirc(ihandler):
	def __init__(self, server, port, username, password, ident, realname, channel):
		self.ident = ident
		self.username = username
		self.realname = realname
		self.client = ircclient(server=server, port=port, realname=realname, ident=ident, username=username, password=password, channel=channel)
		ihandler.__init__(self, '*')

	def __del__(self):
		self.ident = None
		self.realname = None
		self.username = None
		self.client.quit()
		self.client = None

	def start(self):
		self.client.connect()

	def report(self, i, to, xmlobj):
		if self.client is not None and self.client.state != 'online':
			return
		self.client.send_message(xmlobj)

	def handle_incident(self, i):
		try:
			handler_name = i.origin
			handler_name = handler_name.replace('.','_')
			func = getattr(self, "serialize_incident_" + handler_name, None)
		except:
			func = None

		if func is not None and callable(func) == True:
			msg = func(i, anonymous=True)
			if msg is None:
				continue
			self.report(i, to, msg)

	def _serialize_connection(self, i, connection_type, anonymous):
		c = i.con
		local_host = c.local.host
		remote_host = c.remote.host
		remote_hostname = c.remote.hostname

		if anonymous == True:
			if c.remote.hostname == c.local.host:
				remote_host = remote_hostname = local_host = "127.0.0.1"
			else:
				local_host = "127.0.0.1"

		n = etree.Element('connection', attrib={
			'type' : connection_type, 
			'transport' : c.transport,
			'protocol' : c.protocol,
			'local_host' : local_host,
			'local_port' : str(c.local.port),
			'remote_host' : remote_host,
			'remote_hostname' : remote_hostname,
			'remote_port' : str(c.remote.port),
			'ref' : str(c.__hash__())})
		return n

	def serialize_incident_dionaea_connection_tcp_listen(self, i, anonymous):
		return self._serialize_connection(i, 'listen', anonymous)

	def serialize_incident_dionaea_connection_tls_listen(self, i, anonymous):
		return self._serialize_connection(i, 'listen', anonymous)

	def serialize_incident_dionaea_connection_tcp_connect(self, i, anonymous):
		return self._serialize_connection(i, 'connect', anonymous)

	def serialize_incident_dionaea_connection_tls_connect(self, i, anonymous):
		return self._serialize_connection(i, 'connect', anonymous)

	def serialize_incident_dionaea_connection_udp_connect(self, i, anonymous):
		return self._serialize_connection(i, 'connect', anonymous)

	def serialize_incident_dionaea_connection_tcp_accept(self, i, anonymous):
		return self._serialize_connection(i, 'accept', anonymous)

	def serialize_incident_dionaea_connection_tls_accept(self, i, anonymous):
		return self._serialize_connection(i, 'accept', anonymous)

	def serialize_incident_dionaea_connection_tcp_reject(self, i, anonymous):
		return self._serialize_connection(i, 'reject', anonymous)

	def serialize_incident_dionaea_connection_link(self, i, anonymous):
		return etree.Element('link', attrib={
			'child' : str(i.child.__hash__()),
			'parent' : str(i.parent.__hash__())
			})

	def serialize_incident_dionaea_connection_free(self, i, anonymous):
		return etree.Element('connection', attrib={
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_module_emu_profile(self, i, anonymous):
		n = etree.Element('profile', attrib={
			'ref' : str(i.con.__hash__())})
		n.text = str(json.loads(i.profile))
		return n

	def serialize_incident_dionaea_download_offer(self, i, anonymous):
		return etree.Element('offer', attrib={
			'url' : i.url,
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_download_complete_hash(self, i, anonymous):
		if not hasattr(i, 'con'):
			return

		# do not announce files gatherd via xmpp
		if i.con == self.client:
			return
		return etree.Element('download', attrib={
			'url' : i.url,
			'md5_hash' : i.md5hash,
			'ref' : str(i.con.__hash__())})


	def serialize_incident_dionaea_download_complete_unique(self, i, anonymous):
		# do not broadcast files gatherd via xmpp
		if hasattr(i, 'con') and i.con == self.client:
			return

		n = etree.Element('file', attrib={
			'md5_hash' : i.md5hash
			})
		f = open(i.file, "rb")
		m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
		n.text = base64.b64encode(m.read(m.size())).decode('utf-8')
		m.close()
		f.close()
		return n

	def serialize_incident_dionaea_service_shell_listen(self, i, anonymous):
		pass

	def serialize_incident_dionaea_service_shell_connect(self, i, anonymous):
		pass

	def serialize_incident_dionaea_modules_python_p0f(self, i, anonymous):
		pass

	def serialize_incident_dionaea_modules_python_smb_dcerpc_request(self, i, anonymous):
		return etree.Element('dcerpcrequest', attrib={
			'uuid' : i.uuid,
			'opnum' : str(i.opnum),
			'ref' : str(i.con.__hash__())})
		
	def serialize_incident_dionaea_modules_python_smb_dcerpc_bind(self, i, anonymous):
		return etree.Element('dcerpcbind', attrib={
			'uuid' : i.uuid,
			'transfersyntax' : i.transfersyntax,
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_modules_python_mysql_login(self, i, anonymous):
		return etree.Element('mysqllogin', attrib={
			'username' : i.username,
			'password' : i.password,
			'ref' : str(i.con.__hash__())})

	def serialize_incident_dionaea_modules_python_mysql_command(self, i, anonymous):
		n = etree.Element('mysqlcommand', attrib={
			'cmd' : str(i.command),
			'ref' : str(i.con.__hash__())})
		if hasattr(i,'args'):
			args = etree.SubElement(n,'args')
			for j in range(len(i.args)):
				arg = etree.SubElement(args, 'arg', attrib={
					'index' : str(j)})
				arg.text = i.args[j]
		return n

	def serialize_incident_dionaea_modules_python_sip_command(self, icd, anonymous):
		def mk_uri(uri):
			r = etree.Element('uri')
			for u in ['scheme','user','password','port','host']:
				if u not in uri or uri[u] is None:
					continue
				r.set(u, uri[u])
			return r

		def mk_addr(_type, addrs):
			r = etree.Element(_type)
			for addr in addrs:
				a = etree.SubElement(r,'addr')
				if addr['display_name'] is not None:
					a.set('display_name',addr['display_name'])
				a.append(mk_uri(addr['uri']))
			return r

		def mk_via(vias):
			r = etree.Element('vias')
			for via in vias:
				s = etree.SubElement(r,'via')
				for u in ['address','port','protocol','port','host']:
					if u not in via or via[u] is None:
						continue
					s.set(u, via[u])
			return r

		def mk_allow(allows):
			r = etree.Element('allowlist')
			for a in allows:
				e = etree.SubElement(r,'allow')
				e.text = a
			return r

		def mk_sdp(sdp):
			s=etree.Element('sdp')
			if 'o' in sdp:
				o = etree.SubElement(s, 'origin')
				for u in ['username','unicast_address','nettype','addrtype','sess_id','sess_version']:
					if u in sdp['o']:
						o.set(u, sdp['o'][u])
			if 'c' in sdp:
				c = etree.SubElement(s, 'connectiondata')
				for u in ['connection_address','number_of_addresses','addrtype','nettype','ttl']:
					if u in sdp['c']:
						c.set(u, sdp['c'][u])
			if 'm' in sdp:
				m = etree.SubElement(s, 'medialist')
				for media in sdp['m']:
					x = etree.SubElement(m,'media')
					for u in ['proto','port','media','number_of_ports']:
						if u not in media or media[u] is None:
							continue
						x.set(u, media[u])
			return s

		def mk_str(d,_replace):
			def mk_value(v,_replace):
				if isinstance(v,dict) or isinstance(v,list):
					return mk_str(v, _replace=_replace)
				elif isinstance(v,bytes):
					s = v.decode('ascii')
				elif isinstance(v, int):
					s = str(v)
				else:
					s = v
				if _replace is not None:
					s = _replace(s)
				return s

			if isinstance(d,dict):
				b={}
				for k,v in d.items():
					if v is not None:
						b[k] = mk_value(v, _replace)
				return b
			elif isinstance(d,list):
				return [mk_value(v, _replace) for v in filter(lambda x:x is not None,d)]
			else:
				return mk_value(d, _replace)


		n = etree.Element('sipcommand', attrib={
			'method' : str(icd.method),
			'ref' : str(icd.con.__hash__())})

		if anonymous:
			_replace = lambda x: x.replace(icd.con.local.host,'127.0.0.1')
		else:
			_replace = None
		
		if hasattr(icd,'user_agent') and icd.user_agent is not None:
			n.set('user_agent', mk_str(icd.user_agent,_replace))
		n.set('call_id',mk_str(icd.call_id,_replace))
		n.append(mk_addr('address',[mk_str(icd.get('addr'), _replace)]))
		n.append(mk_addr('to',[mk_str(icd.get('to'), _replace)]))
		n.append(mk_addr('contact',[mk_str(icd.get('contact'), _replace)]))
		n.append(mk_addr('from',mk_str(icd.get('from'), _replace)))
		n.append(mk_via(mk_str(icd.get('via'), _replace)))
		n.append(mk_allow(mk_str(icd.get('allow'),_replace)))
		if hasattr(icd,'sdp') and icd.sdp is not None:
			n.append(mk_sdp(mk_str(icd.sdp,_replace)))

		return n

