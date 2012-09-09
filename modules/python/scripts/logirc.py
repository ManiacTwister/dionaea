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
#*******************************************************************************
#
#		Dirty IRC notification module 
#   (c) by ManiacTwister
#
#******************************************************************************/
from dionaea.core import connection, ihandler, g_dionaea, incident
from xml.etree import ElementTree as etree
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
import socket
import re
from threading import Thread

logger = logging.getLogger('logirc')
logger.setLevel(logging.INFO)


def HH(some): return hashlib.md5(some).hexdigest()
def H(some): return hashlib.md5(some).digest()


''' IRC Client begin '''

class ircclient:
    def __init__(self, server, port, realname, ident, nick, password, channel):
        self.server = server
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 
        self.realname = realname
        self.ident = ident
        self.nick = nick
        self.channel = channel
        self.state = "offline"

    def connect(self):
        self.sock.connect((socket.gethostbyname(self.server), self.port))
        self.sendSocket("USER %s %s DIONAEA :%s\r\n" % (self.ident, self.server, self.realname))
        self.sendSocket("NICK %s\r\n" % self.nick)
        self.sendSocket("JOIN %s\r\n" % self.channel)
        self.state = "online"
        logger.info("logirc is online!")
        t = Thread(target=self.server_response, args=(self,))
        t.start()
    def parseMessage(self, message):
        nick = message[message.index(":"):message.index("!")]
        message = message[message.index(":") + 1:]
        message = message[message.index(":"):]
        return "%s %s" % (nick, message)
    def server_response(self, client):
        i=0
        while(client.state != "offline"):
            i=i+1
            client.sendSocket("PRIVMSG %s :%s\r\n" % (client.channel, i))
            response = client.sock.recv(1024).decode('utf-8')
            '''if "!" in response and ":" in response[response.index(":") + 1:]:
                return client.parseMessage(response)'''
            if "PING :" in response:
               client.sendSocket(response.replace("PING", "PONG"))
    def send_message(self, message):
        if not message:
            logger.info("irclog: send_message without message..")
        if self.channel:
            return self.sendSocket("PRIVMSG %s :%s\r\n" % (self.channel, message))
        else:
            logger.info("irclog: no channel defined..")
            return False
    def close(self):
        self.state = "offline"
        self.sock.close()
        return
    def sendSocket(self, data):
        self.sock.send(bytearray(data, 'utf-8'))
        return

''' IRC Client end '''

class logirc(ihandler):
  def __init__(self, server, port, nick, password, ident, realname, channel):
    logger.info("logirc started!")
    self.ident = ident
    self.nick = nick
    self.realname = realname
    self.client = ircclient(server=server, port=port, realname=realname, ident=ident, nick=nick, password=password, channel=channel)
    ihandler.__init__(self, '*')

  def __del__(self):
    self.ident = None
    self.realname = None
    self.nick = None
    self.client.quit()
    self.client = None

  def start(self):
    self.client.connect()

  def stop(self):
    self.client.close()

  def report(self, i, msg):
    if self.client is not None and self.client.state != 'online':
      return
    self.client.send_message(msg)

  def handle_incident(self, i):
    try:
      handler_name = i.origin
      handler_name = handler_name.replace('.','_')
      func = getattr(self, "serialize_incident_" + handler_name, None)
    except:
      func = None

    if func is not None and callable(func) == True:
      msg = func(i, True)
      if msg is None:
        return
      self.report(i, msg)

  def _serialize_connection(self, i, connection_type, anonymous):
    c = i.con
    
    local_host = c.local.host
    remote_host = c.remote.host
    remote_hostname = c.remote.hostname

    # Anonymize ip-adresses
    if anonymous == True:
      if c.remote.hostname == c.local.host:
        remote_host = remote_hostname = local_host = "127.0.0.1"
      else:
        local_host = "127.0.0.1"

    return "%s %s %s %s:%s %s/%s:%s %s" % (connection_type, c.protocol, c.transport, local_host, c.local.port, remote_hostname, remote_host, c.remote.port, c.__hash__())

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
    return "link %s %s" % (i.parent.__hash__(), i.child.__hash__())

  def serialize_incident_dionaea_connection_free(self, i, anonymous):
    return "free %i" % i.con.__hash__()

  def serialize_incident_dionaea_module_emu_profile(self, i, anonymous):
   return "profile ref %s: %s" % (i.profile, i.con.__hash__())

  def serialize_incident_dionaea_download_offer(self, i, anonymous):
    return "offer ref %i: %s" % (i.con.__hash__(), i.url)

  def serialize_incident_dionaea_download_complete_hash(self, i, anonymous):
    # do not announce files gatherd via irc
    if i.con == self.client:
      return

    return "complete ref %s: %s %s" % (i.con.__hash__(), i.url, i.md5hash)


  def serialize_incident_dionaea_download_complete_unique(self, i, anonymous):
    # do not broadcast files gatherd via xmpp
    if hasattr(i, 'con') and i.con == self.client:
      return

    f = open(i.file, "rb")
    m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    my_hash = md5.new(m.read(m.size())).hexdigest()
    m.close()
    f.close()

    return "file %s <-> %s" % (md5_hash, my_hash)

  def serialize_incident_dionaea_service_shell_listen(self, i, anonymous):
    pass

  def serialize_incident_dionaea_service_shell_connect(self, i, anonymous):
    pass

  def serialize_incident_dionaea_modules_python_p0f(self, i, anonymous):
    pass

  def serialize_incident_dionaea_modules_python_smb_dcerpc_request(self, i, anonymous):
    return "dcerpcrequest ref %i: %s %s" % (i.con.__hash__(), i.uuid, i.opnum)
    
  def serialize_incident_dionaea_modules_python_smb_dcerpc_bind(self, i, anonymous):
    return "dcerpcbind ref %i: %s %s" % (i.con.__hash__(), i.uuid, i.transfersyntax)




  def handle_incident_dionaea_modules_python_mssql_login(self, i):
    return "mssqllogin ref %i: %s %s" % (i.con.__hash__(), i.username, i.password)

  def handle_incident_dionaea_modules_python_mssql_cmd(self, i):
    return "mssqlcommand ref %i: %i %s" % (i.con.__hash__(), i.command, i.args)


  def handle_incident_dionaea_modules_python_virustotal_report(self, i):
    pass


  def serialize_incident_dionaea_modules_python_mysql_login(self, i, anonymous):
    return "mysqllogin ref %i: %s %s" % (i.con.__hash__(), i.username, i.password)

  def serialize_incident_dionaea_modules_python_mysql_command(self, i, anonymous):
    return "mysqlcommand ref %i: %i %s" % (i.con.__hash__(), i.command, i.args)

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
    ''' return '''
    return "sipcommand ref %i: %s %s" % (icd.con.__hash__(), icd.method, icd.get('addr'))
