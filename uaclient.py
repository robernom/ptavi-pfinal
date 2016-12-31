#!/usr/bin/python3
# -*- coding: utf-8 -*-

Resp = [100, 180, 200, 400, 401, 404, 405]
"""Programa cliente UDP que abre un socket a un servidor."""
import socket
import sys
import hashlib as HL
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

    def methods(self, met, info):
        if met == "REGISTER":
            text = (met + " sip:" + NAME + ':' + SERVER[1] + 
                    " SIP/2.0\r\nExpires: " + info + '\r\n\r\n')
            my_socket.send(bytes(text, 'utf-8'))
        elif met == "INVITE":
            text = (met + " sip:{} " + " SIP/2.0\r\n"
                    + "Content-Type: application/sdp\r\n\r\nv=0\r\no={} {}\r\n"
                    + "s=Conver\r\nt=0\r\nm=audio {} RTP")
            text = text.format(info, NAME, SERVER[0], PORTP)
            my_socket.send(bytes(text, 'utf-8'))


if __name__ == "__main__":
    try:
        CONFIG, MET, OPT = sys.argv[1:]
    except ValueError:
        sys.exit("Usage: python3 uaclient.py config method option")
    cHandler = UAHandler(CONFIG)
    NAME = cHandler.config['account']['username']
    PASS = cHandler.config['account']['passwd']
    SERVER = [cHandler.config['uaserver']['ip'], 
              cHandler.config['uaserver']['puerto']]
    PORTP = cHandler.config['rtpaudio']['puerto']
    REGPROX = (cHandler.config['regproxy']['ip'],
               cHandler.config['regproxy']['puerto'])
    LOG_PATH = cHandler.config['log']['path']
    AUD_PATH = cHandler.config['audio']['path']
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.connect((REGPROX[0],int(REGPROX[1])))
        cHandler.methods(MET, OPT)
        try:
            DATA = my_socket.recv(1024).decode('utf-8')
            print(DATA)
        except ConnectionRefusedError:
            sys.exit("Error: No server listening at " + REGPROX[0] + " port: " 
                     + REGPROX[1])
        if DATA.split()[1] == "401":
            nonce = DATA.split('"')[-2] #nonce sin \r\n\r\n
            resp = HL.md5((nonce + PASS).encode()).hexdigest()
            text = ("REGISTER" + " sip:" + NAME + ':' + SERVER[1] + 
                    " SIP/2.0\r\nExpires: " + OPT + '\r\n' + "Authorization: "
                    + 'Digest response="' + resp + '"\r\n\r\n')
            my_socket.send(bytes(text, 'utf-8'))
            try:
                DATA = my_socket.recv(1024).decode('utf-8')
                print(DATA)
            except ConnectionRefusedError:
                sys.exit("Error: No server listening at " + REGPROX[0] + 
                         " port: " + REGPROX[1])
        RECV = DATA.split("\r\n\r\n")[0:-1]
        if RECV == ["SIP/2.0 100 Trying", "SIP/2.0 180 Ring", "SIP/2.0 200 OK"]:
            text = ("ACK sip:" + NAME + " SIP/2.0\r\n\r\n")
        