#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Clase (y programa principal) para un servidor de eco en UDP simple."""

import socketserver
import sys
import json
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from time import time, gmtime, strftime


class UAHandler(ContentHandler):

    def __init__(self,xml):  
        self.dtd = {'server': ('name','ip','puerto'), 
                    'log': ('path',),
                    'database': ('path','passwdpath')}
        self.config = {tag: {} for tag in self.dtd}
        parser = make_parser()
        parser.setContentHandler(self)
        parser.parse(xml)

    def startElement(self, name, attrs):
        if name in self.dtd:
            for elem in self.dtd[name]:
                self.config[name][elem] = attrs.get(elem, "")

class SIPHandler(socketserver.DatagramRequestHandler):
    """SIP server class."""
    user_data = {}

    def json2registered(self):
        """Busca fichero JSON con clientes; si no hay devuelve dicc vacio."""
        try:
            with open('users.json') as f_json:
                self.user_data = json.load(f_json)
        except FileNotFoundError:
            self.user_data = {}

    def register2json(self):
        """Introduce en un fichero JSON los usuarios."""
        with open('users.json', 'w') as f_json:
            json.dump(self.user_data, f_json, sort_keys=True, indent=4)

    def handle(self):
        """Cada vez que un cliente envia una peticion se ejecuta."""
        data = self.rfile.read().decode('utf-8')
        print(data)
        c_data = data.split()[1:]
        allowed = ["INVITE", "ACK", "BYE"]
        met = data.split()[0]
        to_send = ""
        if met == "REGISTER":
            # Extracción de información del usuario
            u_name, u_port = c_data[0].split(':')[1:]
            u_ip, u_exp = self.client_address[0], c_data[-1]
            # Controlando el tiempo
            now = int(time())
            str_now = strftime('%Y-%m-%d %H:%M:%S', gmtime(now))
            time_exp = int(u_exp) + now
            str_exp = strftime('%Y-%m-%d %H:%M:%S', gmtime(time_exp))
            self.user_data[u_name] = {'address': u_ip, 'expires': str_exp,
                                      'port': u_port} 
            lista_expirados = []
            for user in self.user_data:
                if self.user_data[user]['expires'] <= str_now:
                    lista_expirados.append(user)
            for name in lista_expirados:
                del self.user_data[name]
            self.register2json()
            to_send = "SIP/2.0 200 OK\r\n\r\n"
        elif met == "INVITE":
            to_send = ("SIP/2.0 100 Trying\r\n\r\nSIP/2.0 180 Ring\r\n\r\n" +
                       "SIP/2.0 200 OK\r\n\r\n")
        elif met == "BYE":
            to_send = "SIP/2.0 200 OK\r\n\r\n"
        elif met == "ACK":
            os.system("./mp32rtp -i " + c_ip + " -p 23032 <")
        elif met not in allowed:
            to_send = "SIP/2.0 405 Method Not Allowed\r\n\r\n"
        elif not authorized:
            to_send = "SIP/2.0 401 Unauthorized\r\n\r\n"
        elif USER not in usr_list:
            to_send = "SIP/2.0 404 User Not Found\r\n\r\n"
        else:
            to_send = "SIP/2.0 400 Bad Request\r\n\r\n"
        if to_send != "":
            self.wfile.write(bytes(to_send, 'utf-8'))

if __name__ == "__main__":
    # Creamos servidor y escuchamos
    try:
        CONFIG = sys.argv[1]
        cHandler = UAHandler(CONFIG)
        SERVER = (cHandler.config['server']['ip'], 
                  int(cHandler.config['server']['puerto']))
    except (IndexError, ValueError):
        sys.exit("Usage: python3 server.py config")
    SERV = socketserver.UDPServer(SERVER, SIPHandler)
    print("Listening...")
    try:
        SERV.serve_forever()
    except KeyboardInterrupt:
        sys.exit("\r\nClosed")
