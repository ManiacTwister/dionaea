import socket
import os
from threading import Thread
import logging
import errno
from time import sleep
import ssl as ssl_mod

logging.basicConfig(filename='irclog.log', format='%(asctime)s;%(levelname)s;%(message)s', level=logging.DEBUG)


''' IRC Client begin '''


class ircclient:
    def __init__(self, server, port, realname, ident, nick, password, channel, ssl, adminhost, adminpw):
        self.server = server
        self.port = port

        self.realname = realname
        self.ident = ident
        self.nick = nick
        self.channel = channel
        self.state = "offline"
        self.ssl = ssl
        self.adminhost = adminhost
        self.adminpw = adminpw

        #light red
        #purple
        #pink
        #light green
        #dark grey
        self.colors = {
            'crit': "\x03\x34",
            'warn': "\x03\x36",
            'debug': "\x03\x31\x33",
            'info': "\x03\x39",
            'spam': "\x03\x31\x34"
        }

    def connect(self):
        logging.info("[IRC] Connecting to IRC")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((socket.gethostbyname(self.server), self.port))
            #self.sock.settimeout(120)
            if self.ssl:
                self.ssl = ssl_mod.wrap_socket(self.sock)
            logging.info("[IRC] Connected to IRC")
            self.sendSocket("USER %s %s DIONAEA :%s\r\n" % (self.ident, self.server, self.realname))
            self.sendSocket("NICK %s\r\n" % self.nick)
            self.sendSocket("JOIN %s\r\n" % self.channel)
            self.state = "online"
            logging.info("[IRC] Joined channel")
            self.t = Thread(target=self.server_response, args=(self,))
            self.t.start()
        except socket.error as v:
            if v.errno == errno.ECONNREFUSED:
                logging.warning("[IRC] Connection refused, retrying in 5 seconds")
            else:
                logging.warning("[IRC] Connection failed, retrying in 5 seconds: %s" % v)
            sleep(5)
            self.connect()
        except Exception as v:
            logging.warning("[IRC] Connection failed, retrying in 5 seconds: %s" % v)
            sleep(5)
            self.connect()

    def parseMessage(self, s):
        try:
            s = s.rstrip()
            """Breaks a message from an IRC server into its prefix, command, and arguments.
            """
            prefix = ''
            trailing = []
            if not s:
                return
            if s[0] == ':':
                prefix, s = s[1:].split(' ', 1)
            if s.find(' :') != -1:
                s, trailing = s.split(' :', 1)
                args = s.split()
                args.append(trailing)
            else:
                args = s.split()
            command = args.pop(0)
            nick, host = prefix.split("!")
            dest = args.pop(0)
            cmd = args[0].split(" ")

            logging.debug("[IRC] Received command: %s %s %s %s" % (nick, host.replace("~", ""), dest, cmd[0]))
            if len(cmd) >= 1:
                if "!opme" in cmd[0] and len(cmd) >= 2:
                    logging.debug("[IRC] Received command !opme from %s with pw %s and host %s and pw %s and chan %s" % (nick, cmd[1], self.adminhost, self.adminpw, dest))
                    if cmd[1] == self.adminpw and host.replace("~", "") == self.adminhost:
                        self.sendSocket("MODE %s +o %s" % (dest, nick))
                        logging.debug("[IRC] Opped %s: MODE %s +o %s" % (nick, dest, nick))
        except:
            return

    def server_response(self, client):
        #i = 0
        while(client.state != "offline" and self.state != "offline"):
            try:
                #i = i + 1
                #logger.debug("PRIVMSG %s :%s" % (client.channel, i))
                #client.sendSocket("PRIVMSG %s :%s\r\n" % (client.channel, i))
                response = self.recvSocket()
                if len(response) <= 0:
                    return
                '''if "!" in response and ":" in response[response.index(":") + 1:]:
                    return client.parseMessage(response)'''
                if "PING :" in response:
                    client.sendSocket(response.replace("PING", "PONG"))
                    logging.debug("[IRC] Received PING")
                elif "PRIVMSG " in response:
                    self.parseMessage(response)
                else:
                    logging.debug("[IRC] Received MSG: %s" % response)
            except KeyboardInterrupt:
                #break
                pass
        return

    def send_message(self, message, type="info"):
        if not message:
            logging.warning("[IRC] Executed send_message without a message")
            return
        if self.channel:
            return self.sendSocket("PRIVMSG %s :%s%s\r\n" % (self.channel, self.colors[type], message))
        else:
            logging.warning("[IRC] Executed send_message without a defined channel")
            return False

    def close(self, msg=""):
        logging.info("[IRC] Disconnected from IRC")
        self.sendSocket("QUIT :%s" % msg)
        self.state = "offline"
        self.sock.close()
        return

    def sendSocket(self, data):
        try:
            data = bytearray(data, 'utf-8')
            if self.ssl:
                self.ssl.write(data)
            else:
                self.sock.send(data)
        except Exception as e:
            logging.warn("[IRC] Error sending to socket: %s" % e)
        return

    def recvSocket(self):
        data = str()
        while data.find("\r") == -1:
            chunk = str()
            try:
                if self.ssl:
                    chunk = self.ssl.read()
                else:
                    chunk = self.sock.recv(4096)
                chunk = chunk.decode('utf-8')
            except:
                pass

            if chunk == None:
                self.close()
                sleep(5)
                self.connect()
                break
            elif len(chunk) <= 0:
                self.close()
                sleep(5)
                self.connect()
                break
            else:
                data += chunk
        return data

    '''def setAdminPw(self, host, pw):
        self.adminpw = pw
        self.adminhost = host'''

''' IRC Client end '''


class daemon:
    def __init__(self):
        self.client = None
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            os.remove("/tmp/ircdaemon")
        except OSError:
            pass

        s.bind("/tmp/ircdaemon")
        logging.info("[LOCAL] Waiting for a connection")
        s.listen(1)
        self.conn, self.addr = s.accept()
        t = Thread(target=self.recvLocalSocket, args=(self,))
        t.start()

    def __del__(self):
        self.conn = None
        self.addr = None
        self.client = None
        self.adminpw = None

    def recvLocalSocket(self, daemon):
        logging.info("[LOCAL] Dionaea connected")
        while True:
            try:
                data = daemon.conn.recv(4096)
            except socket.timeout:
                logging.warning("[LOCAL] Timeout reveiving localsocket")
                continue
            except KeyboardInterrupt:
                #break
                pass

            if not data:
                continue

            data = data.decode('utf-8')
            data = data.split(':s:')

            if data[0] == "MSG" and daemon.client.state != "offline":
                logging.debug("[LOCAL] Received MSG:%s" % data[1])
                if len(data) >= 3:
                    daemon.client.send_message(data[2], data[1])
                else:
                    daemon.client.send_message(data[1])
            elif data[0] == "CONNECT":
                logging.debug("[LOCAL] Received CONNECT:%s:%i:%s:%s:%s:*****:%s" % (data[1], int(data[2]), data[3], data[4], data[5], data[7]))
                daemon.client = ircclient(server=data[1], port=int(data[2]), realname=data[3], ident=data[4], nick=data[5], password=data[6], channel=data[7], ssl=bool(data[8]), adminhost=data[9], adminpw=data[10])
                daemon.client.connect()
            elif data[0] == "DISCONNECT":
                logging.debug("[LOCAL] Received DISCONNECT")
                daemon.client.close("Dionaea requested disconnect")
                daemon.client = None
            '''elif data[0] == "SETADMIN":
                logging.debug("[LOCAL] Received SETADMIN %s:%s" % (data[1], data[2]))
                daemon.adminpw = data[1]
                daemon.client.setAdminCredentials(data[1], data[2])'''
        return

    def closeLocalConnection(self):
        self.conn.close()
        self.conn = None
        self.addr = None

d = daemon()
