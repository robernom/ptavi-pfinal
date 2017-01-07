#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Programa cliente UDP que abre un socket a un servidor."""
import socket
import sys
import hashlib as HL
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from os import system
from time import time, gmtime, strftime

RESP_COD = {100: 'SIP/2.0 100 Trying\r\n', 180: 'SIP/2.0 180 Ring\r\n',
            200: 'SIP/2.0 200 OK'}


class Log:
    """Clase para incluir en un fichero mensajes de log y depuracion."""

    def __init__(self, f_log):
        """Inicializa con el fichero que pasen como parametro."""
        self.log = f_log

    def log_write(self, met, addr, event):
        """Escribe en el fichero el evento."""
        with open(self.log, 'a') as log:
            now = strftime('%Y%m%d%H%M%S', gmtime(int(time()) + 3600))
            if met == "send":
                text = "Send to {}: {}".format(':'.join(addr), event)
            elif met == "recv":
                text = "Received from {}: {}".format(':'.join(addr), event)
            else:
                text = event
            log.write("{} {}\r\n".format(now, text.replace('\r\n', ' ')))


def recv_msg():
    """Imprime y devuelve los datos recibidos."""
    try:
        data = my_socket.recv(1024).decode('utf-8')
        obj_log.log_write("recv", REGPROX, data)
        print(data)
        return data
    except ConnectionRefusedError:
        error = "Error: No server listening at {} port {}"
        obj_log.log_write("", "", error.format(REGPROX[0], REGPROX[1]))
        sys.exit(error.format(REGPROX[0], REGPROX[1]))


def methods(met, info):
    """Envia y recibe mensajes dependiendo del metodo introducido."""
    if met == "REGISTER":
        text = (met + " sip:" + NAME + ':' + SERVER[1] +
                " SIP/2.0\r\nExpires: " + info + '\r\n\r\n')
        my_socket.send(bytes(text, 'utf-8'))
        obj_log.log_write("send", REGPROX, text)
        data = recv_msg()
        if data and data.split()[1] == "401":
            nonce = data.split('"')[-2]     # nonce sin \r\n\r\n
            resp = HL.md5((nonce + PASS).encode()).hexdigest()
            text = ("REGISTER sip:{}:{} SIP/2.0\r\nExpires: {}\r\n" +
                    'Authorization: Digest response="{}"\r\n\r\n')
            text = text.format(NAME, SERVER[1], info, resp)
            my_socket.send(bytes(text, 'utf-8'))
            obj_log.log_write("send", REGPROX, text)
            data = recv_msg()
    elif met == "INVITE":
        text = (met + " sip:{} SIP/2.0\r\n")
        text += ("Content-Type: application/sdp\r\n\r\nv=0\r\no={} {}\r\n")
        text += ("s=Conver\r\nt=0\r\nm=audio {} RTP\r\n\r\n")
        text = text.format(info, NAME, SERVER[0], PORTP)
        my_socket.send(bytes(text, 'utf-8'))
        obj_log.log_write("send", REGPROX, text)
        data = recv_msg()
        recv = data.split("Content")[0]
        compare = (RESP_COD[100] + PR_HEADER + RESP_COD[180])
        compare += (RESP_COD[200] + '\r\n')
        if recv == compare:
            dest = data.split('o=')[1].split()[0]
            portp = data.split('m=audio ')[1].split()[0]
            text = ("ACK sip:{} SIP/2.0\r\n\r\n").format(dest)
            my_socket.send(bytes(text, 'utf-8'))
            obj_log.log_write("send", REGPROX, text)
            cmd = "./mp32rtp -i {} -p {} < {}"
            vlc = "cvlc rtp://@{}:{} 2> /dev/null &"
            system(vlc.format(SERVER[0], portp))
            system(cmd.format(SERVER[0], PORTP, AUD_PATH))
    elif met == "BYE":
        text = ("{} sip:{} SIP/2.0\r\n\r\n").format(met, info)
        my_socket.send(bytes(text, 'utf-8'))
        obj_log.log_write("send", REGPROX, text)
        data = recv_msg()
    else:
        text = ("{} sip:{} SIP/2.0\r\n\r\n").format(met, info)
        obj_log.log_write("send", REGPROX, text)
        my_socket.send(bytes(text, 'utf-8'))
        data = recv_msg()
        obj_log.log_write("recv", REGPROX, data)


class UAHandler(ContentHandler):
    """Clase para obtener los valores del xml."""

    def __init__(self, xml):
        """Crea diccionarios para poner los valores."""
        self.dtd = {'account': ('username', 'passwd'), 'audio': ('path',),
                    'uaserver': ('ip', 'puerto'), 'rtpaudio': ('puerto',),
                    'regproxy': ('ip', 'puerto'), 'log': ('path',)}
        self.config = {tag: {} for tag in self.dtd}
        parser = make_parser()
        parser.setContentHandler(self)
        parser.parse(xml)

    def startElement(self, name, attrs):
        """Introduce los valores en los diccionarios."""
        if name in self.dtd:
            for elem in self.dtd[name]:
                self.config[name][elem] = attrs.get(elem, "")

if __name__ == "__main__":
    try:
        CONFIG, MET, OPT = sys.argv[1:]
    except (IndexError, ValueError):
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
    obj_log = Log(LOG_PATH)
    PR_HEADER = "Via: SIP/2.0/UDP {}:{}\r\n".format(REGPROX[0], REGPROX[1])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.connect((REGPROX[0], int(REGPROX[1])))
        obj_log.log_write("", "", "Starting...")
        methods(MET.upper(), OPT)
    obj_log.log_write("", "", "Finishing.")
