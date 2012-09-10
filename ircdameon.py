import socket,os
import re
from threading import Thread

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
        logger.debug("Debugircircircirc")
        while(client.state != "offline"):
            i=i+1
            logger.debug("PRIVMSG %s :%s" % (client.channel, i))
            client.sendSocket("PRIVMSG %s :%s\r\n" % (client.channel, i))
            response = self.recvSocket()
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
    def recvSocket(self):
        data = str()
        while data.find("\r") == -1:
          chunk = self.sock.recv(256).decode('utf-8')
          if chunk == None:
            return
          else:
            data += chunk
        return data
''' IRC Client end '''
print "start"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    os.remove("/tmp/ircdaemon")
except OSError:
    pass

s.bind("/tmp/ircdaemon")
s.listen(1)
conn, addr = s.accept()
s.settimeout(0.1)
while True:
    try:
        data = conn.recv(256)
    except socket.timeout:
        print "timeout"
    finally:
        break;

    if not data: break
    data = data.decode('utf-8')
    print "while2"
    data = data.split(':')
    print data
    if data[0] == "MSG":
        print "MSG"
        client.send_message(data[1])
    if data[0] == "CONNECT":
        print "Connect"
        client = ircclient(server=data[1], port=data[2], realname=data[3], ident=data[4], nick=data[5], password=data[6], channel=data[7])
        client.connect()
conn.close()
