import socket
import os
from threading import Thread
import logging
import sys
import re
import urllib

from twisted.words.protocols import irc
from twisted.internet import protocol, reactor

#logging.basicConfig(filename='irclog.log', level=logging.DEBUG)

''' IRC Client begin


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
        logging.info("Connected to IRC")
        t = Thread(target=self.server_response, args=(self,))
        t.start()

    def parseMessage(self, message):
        nick = message[message.index(":"):message.index("!")]
        message = message[message.index(":") + 1:]
        message = message[message.index(":"):]
        return "%s %s" % (nick, message)

    def server_response(self, client):
        #i = 0
        while(client.state != "offline"):
            try:
                #i = i + 1
                #logger.debug("PRIVMSG %s :%s" % (client.channel, i))
                #client.sendSocket("PRIVMSG %s :%s\r\n" % (client.channel, i))
                response = self.recvSocket()
                if len(response) == 0:
                    client.connect()
                    return
                if "PING :" in response:
                    #client.sendSocket(response.replace("PING", "PONG"))
                    logging.debug("Received PING")
            except KeyboardInterrupt:
                break
        return

    def send_message(self, message):
        if not message:
            logging.warning("Executed send_message without a message")
            return
        if self.channel:
            return self.sendSocket("PRIVMSG %s :%s\r\n" % (self.channel, message))
        else:
            logging.warning("Executed send_message without a defined channel")
            return False

    def close(self):
        logging.info("Disconnected from IRC")
        self.sendSocket("QUIT")
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

IRC Client end '''

class DionaeaBot(irc.IRCClient):
    def _get_nickname(self):
        return self.factory.nickname
    nickname = property(_get_nickname)

    def signedOn(self):
        self.join(self.factory.channel)
        print "Signed on as %s." % (self.nickname)

    def joined(self, channel):
        print "Joined %s." % channel


class DionaeaBotFactory(protocol.ClientFactory):
    protocol = DionaeaBot

    def __init__(self, channel, nickname):
        self.channel = channel
        self.nickname = nickname

    def clientConnectionLost(self, connector, reason):
        print "Lost connection (%s), reconnecting." % reason
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        print "Could not connect: %s" % reason


class daemon:
    def __init__(self):
        #self.client = None
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            os.remove("/tmp/ircdaemon")
        except OSError:
            pass

        s.bind("/tmp/ircdaemon")
        logging.info("Waiting for a connection")
        s.listen(1)
        self.conn, self.addr = s.accept()
        t = Thread(target=self.recvLocalSocket, args=(self,))
        t.start()

    def __del__(self):
        self.conn = None
        self.addr = None
        #self.client = None
        self.channel = None
        self.deffered = None

    def recvLocalSocket(self, daemon):
        logging.info("Dionaea connected")
        while True:
            try:
                data = daemon.conn.recv(256)
            except socket.timeout:
                logging.warning("Timeout reveiving localsocket")
                continue
            except KeyboardInterrupt:
                break

            if not data:
                continue

            data = data.decode('utf-8')
            data = data.split(':')

            if data[0] == "MSG":
                logging.debug("Received MSG:%s" % data[1])
                #daemon.client.send_message(data[1])
                daemon.deffered.msg(self.channel, str(data[1]))
            elif data[0] == "CONNECT":
                logging.debug("Received CONNECT:%s:%i:%s:%s:%s:*****:%s" % (data[1], int(data[2]), data[3], data[4], data[5], data[7], daemon))
                #daemon.client = ircclient(server=data[1], port=int(data[2]), realname=data[3], ident=data[4], nick=data[5], password=data[6], channel=data[7])
                #daemon.client.connect()
                self.channel = data[7]
                irct = Thread(target=self.startIrc, args=(data[1], data[2], data[7], data[5],))
                irct.start()
            elif data[0] == "DISCONNECT":
                #daemon.client.close()
                self.stopIrc()
                #daemon.client = None
        return

    def closeLocalConnection(self):
        self.conn.close()
        self.conn = None
        self.addr = None

    def startIrc(self, server, port, channel, nickname, daemon):
        daemon.deferred = reactor.connectTCP(str(server), int(port), DionaeaBotFactory(str(channel), str(nickname)))
        reactor.run(installSignalHandlers=0)

    def stopIrc(self):
        reactor.stop()

d = daemon()
