import socket
import os
from threading import Thread
import logging


logging.basicConfig(filename='irclog.log', level=logging.DEBUG)

''' IRC Client begin '''


class ircclient:
    def __init__(self, server, port, realname, ident, nick, password, channel):
        self.server = server
        self.port = port

        self.realname = realname
        self.ident = ident
        self.nick = nick
        self.channel = channel
        self.state = "offline"

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((socket.gethostbyname(self.server), self.port))
        self.sendSocket("USER %s %s DIONAEA :%s\r\n" % (self.ident, self.server, self.realname))
        self.sendSocket("NICK %s\r\n" % self.nick)
        self.sendSocket("JOIN %s\r\n" % self.channel)
        self.state = "online"
        logging.info("Connected to IRC")
        self.t = Thread(target=self.server_response, args=(self,))
        self.t.start()

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
                '''if "!" in response and ":" in response[response.index(":") + 1:]:
                    return client.parseMessage(response)'''
                if "PING :" in response:
                    client.sendSocket(response.replace("PING", "PONG"))
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
                self.close()
                self.connect()
            elif len(chunk) <= 0:
                self.close()
                self.connect()
            else:
                data += chunk
        return data

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
        logging.info("Waiting for a connection")
        s.listen(1)
        self.conn, self.addr = s.accept()
        t = Thread(target=self.recvLocalSocket, args=(self,))
        t.start()

    def __del__(self):
        self.conn = None
        self.addr = None
        self.client = None

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

            if data[0] == "MSG" and daemon.client.state != "offline":
                logging.debug("Received MSG:%s" % data[1])
                daemon.client.send_message(data[1])
            elif data[0] == "CONNECT":
                logging.debug("Received CONNECT:%s:%i:%s:%s:%s:*****:%s" % (data[1], int(data[2]), data[3], data[4], data[5], data[7]))
                daemon.client = ircclient(server=data[1], port=int(data[2]), realname=data[3], ident=data[4], nick=data[5], password=data[6], channel=data[7])
                daemon.client.connect()
            elif data[0] == "DISCONNECT":
                daemon.client.close()
                daemon.client = None
        return

    def closeLocalConnection(self):
        self.conn.close()
        self.conn = None
        self.addr = None

d = daemon()
