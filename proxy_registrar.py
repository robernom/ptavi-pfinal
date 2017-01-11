#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Programa que actua como proxy-registrar en UDP."""
import socketserver
import socket
import sys
import json
import hashlib as HL
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from time import time, gmtime, strftime
from random import choice, randrange
from uaclient import Log

RESP_COD = {100: 'SIP/2.0 100 Trying\r\n', 180: 'SIP/2.0 180 Ring\r\n',
            200: 'SIP/2.0 200 OK',
            400: 'SIP/2.0 400 Bad Request\r\n\r\n',
            401: ('SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: ' +
                  'Digest nonce="{}"\r\n\r\n'),
            404: 'SIP/2.0 404 User Not Found\r\n\r\n',
            405: 'SIP/2.0 405 Method Not Allowed'}
HEX = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd']
HEX += ['e', 'f']


def add_header(data):
    """Introduce cabecera proxy en los mensajes que se van a reenviar."""
    div = data.split("\r\n", 1)
    return "{}\r\n{}\r\n{}".format(div[0], PR_HEADER, div[1])


def new_nonce():
    """Crea un nuevo nonce con digitos hexadecimales pseudoaleatorios."""
    return ''.join(choice(HEX) for i in range(randrange(0, 20)))


def search_pass(name):
    """Busca password del usuario pasado como parametro."""
    with open(PASSWD_PATH) as f_pass:
        try:
            for line in f_pass:
                if line.split(':')[0] == name:
                    passwd = line.split(':')[1][0:-1]
                    break
                else:
                    passwd = ""
            return passwd
        except FileNotFoundError:
            sys.exit("Password file not found")


class PRHandler(ContentHandler):
    """Clase para obtener los valores del xml."""

    def __init__(self, xml):
        """Crea los diccionarios para introducir los valores."""
        self.dtd = {'server': ('name', 'ip', 'puerto'),
                    'log': ('path',),
                    'database': ('path', 'passwdpath')}
        self.config = {tag: {} for tag in self.dtd}
        parser = make_parser()
        parser.setContentHandler(self)
        parser.parse(xml)

    def startElement(self, name, attrs):
        """Introduce los valores en el diccionario."""
        if name in self.dtd:
            for elem in self.dtd[name]:
                self.config[name][elem] = attrs.get(elem, "")


class SIPHandler(socketserver.DatagramRequestHandler):
    """Clase para un servidor SIP."""

    user_data = {}

    def json2registered(self):
        """Busca fichero JSON con clientes; si no hay devuelve dicc vacio."""
        try:
            with open(DBASE) as f_json:
                self.user_data = json.load(f_json)
        except FileNotFoundError:
            self.user_data = {}

    def delete_users(self, moment):
        """Borra los usuarios expirados."""
        lista_expirados = []
        for user in self.user_data:
            if self.user_data[user]['expires'] <= moment:
                lista_expirados.append(user)
        for name in lista_expirados:
            del self.user_data[name]

    def register2json(self):
        """Introduce en un fichero JSON los usuarios."""
        with open(DBASE, 'w') as f_json:
            json.dump(self.user_data, f_json, sort_keys=True, indent=4)

    def register(self, data):
        """Metodo REGISTER."""
        c_data = data.split()[1:]
        # Extracción de información del usuario
        u_name, u_port = c_data[0].split(':')[1:]
        u_ip, u_exp = self.client_address[0], c_data[3]
        u_pass = search_pass(u_name)
        # Controlando el tiempo
        time_exp = int(u_exp) + int(time())
        str_exp = strftime('%Y-%m-%d %H:%M:%S', gmtime(time_exp))
        nonce = new_nonce()
        if u_name not in self.user_data:
            self.user_data[u_name] = {'addr': u_ip, 'expires': str_exp,
                                      'port': u_port, 'auth': False,
                                      'nonce': nonce}

            to_send = RESP_COD[401].format(nonce)
        elif not self.user_data[u_name]['auth']:
            try:
                resp = data.split('"')[-2]
            except IndexError:
                resp = ""
            u_nonce = self.user_data[u_name]['nonce']
            expect = HL.md5((u_nonce + u_pass).encode()).hexdigest()
            if resp == expect:
                self.user_data[u_name]['auth'] = True
                self.user_data[u_name]['expires'] = str_exp
                to_send = (RESP_COD[200] + "\r\n\r\n")
            else:
                to_send = RESP_COD[401].format(nonce)
        else:
            to_send = (RESP_COD[200] + "\r\n\r\n")
        self.register2json()
        self.wfile.write(bytes(to_send, 'utf-8'))
        obj_log.log_write("send", (u_ip, u_port), to_send)

    def invite(self, data):
        """Metodo INVITE."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            dest = data.split()[1][4:]
            try:
                (ip_port) = (self.user_data[dest]['addr'],
                             int(self.user_data[dest]['port']))
                sock.connect(ip_port)
                text = add_header(data)
                sock.send(bytes(text, 'utf-8'))
                recv = sock.recv(1024).decode('utf-8')
            except (ConnectionRefusedError, KeyError):
                recv = ""
                self.wfile.write(bytes(RESP_COD[404], 'utf-8'))
        if recv.split('\r\n')[0:3] == [RESP_COD[100][0:-2],
                                       RESP_COD[180][0:-2], RESP_COD[200]]:
            text = add_header(recv)
            print(text)
            self.socket.sendto(bytes(text, 'utf-8'), self.client_address)
        try:
            if recv.split()[1] and recv.split()[1] == "480":
                text = add_header(recv)
                self.socket.sendto(bytes(text, 'utf-8'), self.client_address)
        except IndexError:
            pass

    def ack(self, data):
        """Metodo ACK."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            dest = data.split()[1][4:]
            (ip_port) = (self.user_data[dest]['addr'],
                         int(self.user_data[dest]['port']))
            sock.connect(ip_port)
            text = add_header(data)
            sock.send(bytes(text, 'utf-8'))
            try:
                recv = sock.recv(1024).decode('utf-8')
                print(recv)
            except socket.timeout:
                pass

    def bye(self, data):
        """Metodo BYE."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                dest = data.split()[1][4:]
                (ip_port) = (self.user_data[dest]['addr'],
                             int(self.user_data[dest]['port']))
                sock.connect(ip_port)
                text = add_header(data)
                sock.send(bytes(text, 'utf-8'))
                recv = sock.recv(1024).decode('utf-8')
            except (ConnectionRefusedError, KeyError):
                recv = ""
                self.wfile.write(bytes(RESP_COD[404], 'utf-8'))
        if recv == (RESP_COD[200] + "\r\n\r\n"):
            text = add_header(recv)
            self.socket.sendto(bytes(text, 'utf-8'), self.client_address)

    def handle(self):
        """Cada vez que un cliente envia una peticion se ejecuta."""
        data = self.request[0].decode('utf-8')
        c_addr = (self.client_address[0], str(self.client_address[1]))
        obj_log.log_write("recv", c_addr, data)
        unallow = ["CANCEL", "OPTIONS", "SUSCRIBE", "NOTIFY", "PUBLISH",
                   "INFO", "PRACK", "REFER", "MESSAGE", "UPDATE"]
        print(data)
        met = data.split()[0]
        self.json2registered()
        str_now = strftime('%Y-%m-%d %H:%M:%S', gmtime(int(time())))
        self.delete_users(str_now)
        if met == "REGISTER":
            self.register(data)
        elif met == "INVITE":
            self.invite(data)
        elif met == "ACK":
            self.ack(data)
        elif met == "BYE":
            self.bye(data)
        elif met in unallow:
            to_send = "SIP/2.0 405 Method Not Allowed\r\n\r\n"
            obj_log.log_write("send", c_addr, to_send)
            self.wfile.write(bytes(to_send, 'utf-8'))
        else:
            to_send = "SIP/2.0 400 Bad Request\r\n\r\n"
            obj_log.log_write("send", c_addr, to_send)
            self.wfile.write(bytes(to_send, 'utf-8'))

if __name__ == "__main__":
    # Creamos servidor y escuchamos
    try:
        CONFIG = sys.argv[1]
        cHandler = PRHandler(CONFIG)
        NAME = cHandler.config['server']['name']
        SERVER = (cHandler.config['server']['ip'],
                  int(cHandler.config['server']['puerto']))
        LOG_PATH = cHandler.config['log']['path']
        obj_log = Log(LOG_PATH)
        DBASE = cHandler.config['database']['path']
        PASSWD_PATH = cHandler.config['database']['passwdpath']
        PR_HEADER = "Via: SIP/2.0/UDP {}:{}".format(SERVER[0], SERVER[1])
    except (IndexError, ValueError):
        sys.exit("Usage: python3 server.py config")
    SERV = socketserver.UDPServer(SERVER, SIPHandler)
    OK = "Server {} listening at port {}... ".format(SERVER[0], SERVER[1])
    print(OK)
    obj_log.log_write("", "", OK)
    try:
        SERV.serve_forever()
    except KeyboardInterrupt:
        sys.exit("\r\nClosed")
