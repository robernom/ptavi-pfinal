#!/usr/bin/python3
# -*- coding: utf-8 -*-
Met = ["REGISTER", "ACK", "INVITE", "BYE"]
Resp = [100, 180, 200, 400, 401, 404, 405]
"""Programa cliente UDP que abre un socket a un servidor."""
import socket
import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

class UAHandler(ContentHandler):

    def __init__(self,xml):  
        self.dtd = {'account': ('username','passwd'), 'audio': ('path',),
                    'uaserver':('ip','puerto'), 'rtpaudio': ('puerto',), 
                    'regproxy': ('ip', 'puerto'), 'log': ('path',)}
        self.config = {tag: {} for tag in self.dtd}
        parser = make_parser()
        parser.setContentHandler(self)
        parser.parse(xml)
    
    def startElement(self, name, attrs):
        if name in self.dtd:
            for elem in self.dtd[name]:
                self.config[name][elem] = attrs.get(elem, "")


if __name__ == "__main__":
    try:
        CONFIG, MET, OPT = sys.argv[1:]
        cHandler = UAHandler(CONFIG)
        SERVER = (cHandler.config['regproxy']['ip'], 
                  int(cHandler.config['regproxy']['puerto']))
        ME = [cHandler.config['account']['username'], 
              cHandler.config['uaserver']['puerto']]

    except ValueError:
        sys.exit("Usage: python3 uaclient.py config method option")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.connect(SERVER)
        MESSAGE = (MET.upper() + " sip:" + ':'.join(ME) + " SIP/2.0\r\n"
                   + "Expires: " + sys.argv[-1]+ '\r\n\r\n')
        my_socket.send(bytes(MESSAGE, 'utf-8'))
        try:
            DATA = my_socket.recv(1024).decode('utf-8')
            print(DATA)
        except ConnectionRefusedError:
            sys.exit("Error: No server listening at " +
                     str(SERVER[0]) + " port: " + str(SERVER[1]))
        EXPECT = DATA.split("\r\n\r\n")[0:-1]
        if EXPECT == ["SIP/2.0 100 Trying", "SIP/2.0 180 Ring", "SIP/2.0 200 OK"]:
            MESSAGE = ("ACK sip:" + ME[0] + " SIP/2.0\r\n\r\n")
            my_socket.send(bytes(MESSAGE, 'utf-8'))