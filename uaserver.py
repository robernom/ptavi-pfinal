#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Clase (y programa principal) para un servidor de eco en UDP simple."""
import socketserver
import sys
from os import system
from threading import Thread
from uaclient import UAHandler, Log

RESP_COD = {100: 'SIP/2.0 100 Trying\r\n', 180: 'SIP/2.0 180 Ring\r\n',
            200: 'SIP/2.0 200 OK', 480: 'SIP/2.0 480 Temporarily Unavailable'}


def vlc(ip_addr, port):
    """Ejecuta el comando que llama vlc para que escuche."""
    system("cvlc rtp://@{}:{} 2> /dev/null".format(ip_addr, port))


def mp3():
    """Ejecuta el comando que llama a mp32rtp para que transmita."""
    system("./mp32rtp -i {} -p {} < {}".format(SERVER[0], PORTP, AUD_PATH))


class SIPHandler(socketserver.DatagramRequestHandler):
    """SIP server class."""

    listening = ""

    def handle(self):
        """Cada vez que recibe una peticion se ejecuta."""
        data = self.request[0].decode('utf-8')
        print(data)
        obj_log.log_write("recv", REGPROX, data)
        met = data.split()[0]
        th_vlc = Thread(target=vlc, args=SIPHandler.listening)
        th_mp3 = Thread(target=mp3)
        if met == "INVITE" and not SIPHandler.listening:
            portp = data.split('m=audio ')[1].split()[0]
            iprtp = data.split('o=')[1].split()[1]
            SIPHandler.listening = (iprtp, portp)
            tosend = RESP_COD[100] + RESP_COD[180] + RESP_COD[200] + "\r\n"
            tosend += "Content-Type: application/sdp\r\n\r\nv=0\r\no={} {}\r\n"
            tosend += "s=Conver\r\nt=0\r\nm=audio {} RTP\r\n\r\n"
            tosend = tosend.format(NAME, SERVER[0], PORTP)
            self.wfile.write(bytes(tosend, 'utf-8'))
            obj_log.log_write("send", REGPROX, tosend)
        elif met == "INVITE" and SIPHandler.listening:
            tosend = RESP_COD[480] + "\r\n\r\n"
            self.wfile.write(bytes(tosend, 'utf-8'))
            obj_log.log_write("send", REGPROX, tosend)
        elif met == "ACK":
            th_vlc.start()
            th_mp3.start()
        elif met == "BYE":
            system("pkill -9 vlc")  # Stop listening
            system("pkill -9 mp32rtp")
            SIPHandler.listening = ""
            tosend = (RESP_COD[200] + "\r\n\r\n")
            self.wfile.write(bytes(tosend, 'utf-8'))
            obj_log.log_write("send", REGPROX, tosend)

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except (IndexError, ValueError):
        sys.exit("Usage: python3 uaserver.py config")
    cHandler = UAHandler(CONFIG)
    NAME = cHandler.config['account']['username']
    PASS = cHandler.config['account']['passwd']
    SERVER = (cHandler.config['uaserver']['ip'],
              int(cHandler.config['uaserver']['puerto']))
    PORTP = cHandler.config['rtpaudio']['puerto']
    REGPROX = (cHandler.config['regproxy']['ip'],
               cHandler.config['regproxy']['puerto'])
    LOG_PATH = cHandler.config['log']['path']
    obj_log = Log(LOG_PATH)
    AUD_PATH = cHandler.config['audio']['path']
    SERV = socketserver.UDPServer(SERVER, SIPHandler)
    print("Listening...")
    try:
        SERV.serve_forever()
    except KeyboardInterrupt:
        sys.exit("\r\nClosed")
