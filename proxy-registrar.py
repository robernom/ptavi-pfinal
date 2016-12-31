#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Clase (y programa principal) para un servidor de eco en UDP simple."""

import socketserver
import sys
import json
import os
import hashlib as HL 
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from time import time, gmtime, strftime

RESP_COD = {100: 'SIP/2.0 100 Trying\r\n', 180: 'SIP/2.0 180 Ring\r\n',
            200: 'SIP/2.0 200 OK\r\n\r\n', 
            400: 'SIP/2.0 400 Bad Request\r\n\r\n',
            401: ('SIP/2.0 401 Unauthorized\r\nWWW Authenticate: '
                 + 'Digest nonce="{}"\r\n\r\n'),
            405: 'SIP/2.0 405 Method Not Allowed'}
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
            with open(DBASE) as f_json:
                self.user_data = json.load(f_json)
        except FileNotFoundError:
            self.user_data = {}

    def delete_users(self, time):
        lista_expirados = []
        for user in self.user_data:
            if self.user_data[user]['expires'] <= time:
                lista_expirados.append(user)
        for name in lista_expirados:
            del self.user_data[name]

    def register2json(self):
        """Introduce en un fichero JSON los usuarios."""
        with open(DBASE, 'w') as f_json:
            json.dump(self.user_data, f_json, sort_keys=True, indent=4)

    def search_pass(self, name):
        with open(PASSWD_PATH) as f_pass:
            text = f_pass.readlines()
            for line in text:
                if line.split(':')[0] == name:
                    exit = line.split(':')[1][0:-1]
                    break
                else:
                    exit = ""
            return exit

    def register(self, data):
        c_data = data.split()[1:]
        # Extracción de información del usuario
        u_name, u_port = c_data[0].split(':')[1:]
        u_ip, u_exp = self.client_address[0], c_data[3]
        u_pass = self.search_pass(u_name)
        # Controlando el tiempo
        now = int(time())
        str_now = strftime('%Y-%m-%d %H:%M:%S', gmtime(now))
        time_exp = int(u_exp) + now
        str_exp = strftime('%Y-%m-%d %H:%M:%S', gmtime(time_exp))
        nonce = "123456789"
        if u_name not in self.user_data :
            self.user_data[u_name] = {'address': u_ip, 'expires': str_exp,
                                      'port': u_port, 'auth': False}
            to_send = RESP_COD[401].format(nonce)
        elif not self.user_data[u_name]['auth']:
            resp = data.split('"')[-2]
            expect = HL.md5((nonce + u_pass).encode()).hexdigest()
            print(expect)
            if resp == expect:
                self.user_data[u_name]['auth'] = True
                to_send = RESP_COD[200]
            else:
                to_send = RESP_COD[401].format(nonce)
        elif u_exp == "0":
            del self.user_data[u_name]
            to_send = RESP_COD[200]
        else:
            to_send = RESP_COD[200]
        self.delete_users(str_now)
        self.register2json()
        self.wfile.write(bytes(to_send, 'utf-8'))

    def handle(self):
        """Cada vez que un cliente envia una peticion se ejecuta."""
        self.json2registered()
        data = self.rfile.read().decode('utf-8')
        print(data)
        allowed = ["INVITE", "ACK", "BYE"]
        met = data.split()[0]
        to_send = ""
        if met == "REGISTER":
            self.register(data)
        elif met == "INVITE":
            to_send = ("SIP/2.0 100 Trying\r\n\r\nSIP/2.0 180 Ring\r\n\r\n" +
                       "SIP/2.0 200 OK\r\n\r\n")
        elif met == "BYE":
            to_send = "SIP/2.0 200 OK\r\n\r\n"
        elif met == "ACK":
            os.system("./mp32rtp -i " + "127.0.0.1" + " -p 23032 <")
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
        NAME = cHandler.config['server']['name']
        SERVER = (cHandler.config['server']['ip'], 
                  int(cHandler.config['server']['puerto']))
        LOG_PATH = cHandler.config['log']['path']
        DBASE = cHandler.config['database']['path']
        print(DBASE)
        PASSWD_PATH = cHandler.config['database']['passwdpath']

    except (IndexError, ValueError):
        sys.exit("Usage: python3 server.py config")
    SERV = socketserver.UDPServer(SERVER, SIPHandler)
    print("Server " + NAME + " listening at port " + str(SERVER[1]))
    try:
        SERV.serve_forever()
    except KeyboardInterrupt:
        sys.exit("\r\nClosed")
