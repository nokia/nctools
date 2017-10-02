#!/usr/bin/python
##############################################################################
#                                                                            #
#  ncproxy.py                                                                #
#                                                                            #
#  History Change Log:                                                       #
#                                                                            #
#    1.0  [SW]  2017/09/04    first version                                  #
#    1.1  [SW]  2017/09/05    improved logging, patching, auto-responses     #
#    1.2  [SW]  2017/10/01    add support patch-files                        #
#                                                                            #
#  Objective:                                                                #
#    ncproxy is a transparent logging proxy for NETONF over SSH              #
#                                                                            #
#  License:                                                                  #
#    Licensed under the BSD license                                          #
#    See LICENSE.md delivered with this project for more information.        #
#                                                                            #
#  Author:                                                                   #
#    Sven Wisotzky                                                           #
#    mail:  sven.wisotzky(at)nokia.com                                       #
#                                                                            #
#                                           (c) 2017 by Sven Wisotzky, Nokia #
##############################################################################

"""
NETCONF proxy in Python Version 1.2
Copyright (C) 2015-2017 Nokia. All Rights Reserved.
"""

import binascii
import logging
import os
import paramiko
import socket
import sys
import threading
import time
import traceback
import argparse
import json
import re

if sys.version_info > (3,):
    from urllib.parse import urlparse
else:
    from urlparse import urlparse

__title__ = "ncproxy"
__version__ = "1.2"
__status__ = "released"
__author__ = "Sven Wisotzky"
__date__ = "2017 October 1st"


class ncHandler(paramiko.SubsystemHandler):

    def __init__(self, channel, name, server, username, password):
        paramiko.SubsystemHandler.__init__(self, channel, name, server)
        self.__username = username
        self.__password = password

    def start_subsystem(self, name, transport, channel):
        try:
            log.info('Establish NETCONF over SSH connection to %s:%d user(%s)', url.hostname, url.port or 830, self.__username)
            srv_tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv_tcpsock.connect((url.hostname, url.port or 830))
            srv_transport = paramiko.Transport(srv_tcpsock)
            srv_transport.connect(username=self.__username, password=self.__password)
            srv_channel = srv_transport.open_session()
            srv_channel.invoke_subsystem('netconf')

        except Exception as e:
            # --- close channel/transport to NETCONF client ------------------
            log.warning('NETCONF over SSH to %s failed: %s', url.hostname, str(e))
            channel.close()
            transport.close()
            return

        log.info('NETCONF messaging capture')

        nccbuf = ""
        srvbuf = ""

        while transport.is_active():
            # --- receive bytes from server, append to srvbuf ----------------

            while srv_channel.recv_ready():
                srvbuf += srv_channel.recv(65535)

            # --- extract srvmsgs[] from srvbuf ------------------------------

            srvmsgs = []
            if len(srvbuf) > 4:
                if srvbuf[0:2] != "\n#":
                    base10 = True   # --- base:1.0 framing (EOM) -------------
                    srvmsgs = srvbuf.split("]]>]]>")
                    srvbuf = srvmsgs.pop()
                else:
                    base10 = False  # --- base:1.1 framing (chunks) ----------

                    tmp = ""
                    pos = 0

                    while pos < len(srvbuf) and len(srvbuf) > 4:
                        if srvbuf[pos:pos + 4] == "\n##\n":
                            srvmsgs.append(tmp)
                            tmp = ""
                            srvbuf = srvbuf[pos + 4:]
                            pos = 0
                        elif srvbuf[pos:pos + 2] == "\n#":
                            idx = srvbuf.find("\n", pos + 2)
                            if idx != -1:
                                bytes = int(srvbuf[pos + 2:idx])
                                tmp += srvbuf[idx + 1:idx + 1 + bytes]
                                pos = idx + 1 + bytes
                            else:
                                # --- need to wait for more bytes to come ----
                                break
                        else:
                            log.error('SERVER FRAMING ERROR')
                            srvbuf = ""
                            break

            # --- patch, forward, print NETCONF server messages: srvmsgs[] ---
            for msg in srvmsgs:
                for rule in rules['server-msg-modifier']:
                    msg = rule['regex'].sub(rule['patch'], msg)
                    
                if not base10:
                    buf = "\n#%d\n" % len(msg)
                    channel.send(buf)
                    serverlog.write(buf)

                pos = 0
                while pos < len(msg):
                    if pos + 16384 < len(msg):
                        buf = msg[pos:pos + 16384]
                        pos += 16384
                    else:
                        buf = msg[pos:]
                        pos = len(msg)
                    channel.send(buf)
                    serverlog.write(buf)

                if base10:
                    buf = "]]>]]>"
                else:
                    buf = "\n##\n"
                channel.send(buf)
                serverlog.write(buf)
                serverlog.flush()

            # --- receive bytes from client, append to nccbuf ----------------

            while channel.recv_ready():
                nccbuf += channel.recv(65535)

            # --- extract nccmsgs[] from nccbuf ------------------------------

            nccmsgs = []
            if len(nccbuf) > 4:
                if nccbuf[0:2] != "\n#":
                    base10 = True   # --- base:1.0 framing (EOM) -------------
                    nccmsgs = nccbuf.split("]]>]]>")
                    nccbuf = nccmsgs.pop()
                else:
                    base10 = False  # --- base:1.1 framing (chunks) ----------

                    tmp = ""
                    pos = 0

                    while pos < len(nccbuf) and len(nccbuf) > 4:
                        if nccbuf[pos:pos + 4] == "\n##\n":
                            nccmsgs.append(tmp)
                            tmp = ""
                            nccbuf = nccbuf[pos + 4:]
                            pos = 0
                        elif nccbuf[pos:pos + 2] == "\n#":
                            idx = nccbuf.find("\n", pos + 2)
                            if idx != -1:
                                bytes = int(nccbuf[pos + 2:idx])
                                tmp += nccbuf[idx + 1:idx + 1 + bytes]
                                pos = idx + 1 + bytes
                            else:
                                # --- need to wait for more bytes to come ----
                                break
                        else:
                            log.error('CLIENT FRAMING ERROR')
                            nccbuf = ""
                            break

            # --- patch, forward, print NETCONF client messages: nccmsgs[] ---
            for msg in nccmsgs:
                for rule in rules['client-msg-modifier']:
                    msg = rule['regex'].sub(rule['patch'], msg)
                    
                sendmsg = True
                for rule in rules['auto-respond']:
                    if rule['regex'].match(msg):
                        log.info('Auto-response to NETCONF client message')
                        tmp = rule['regex'].sub(rule['response'], msg)
                        if base10:
                            srvbuf += tmp
                            srvbuf += "]]>]]>"
                        else:
                            srvbuf += "\n#%d\n" % len(tmp)
                            srvbuf += tmp
                            srvbuf += "\n##\n"
                        sendmsg = False
                        break
            
                if not base10:
                    buf = "\n#%d\n" % len(msg)
                    if sendmsg:
                        srv_channel.send(buf)
                    clientlog.write(buf)

                pos = 0
                while pos < len(msg):
                    if pos + 16384 < len(msg):
                        buf = msg[pos:pos + 16384]
                        pos += 16384
                    else:
                        buf = msg[pos:]
                        pos = len(msg)
                    if sendmsg:
                        srv_channel.send(buf)
                    clientlog.write(buf)

                if base10:
                    buf = "]]>]]>"
                else:
                    buf = "\n##\n"
                if sendmsg:
                    srv_channel.send(buf)
                clientlog.write(buf)
                clientlog.flush()

            if srv_channel.exit_status_ready():
                break
            if channel.exit_status_ready():
                break
            time.sleep(0.01)

        else:
            serverlog.flush()
            clientlog.flush()
            log.info('NETCONF communication finished')

        if srv_channel.exit_status_ready():
            log.warning("Connection closed by peer; server down")
        if channel.exit_status_ready():
            log.warning("Connection closed by peer; client down")

        # --- close channel/transport to NETCONF server ----------------------
        srv_channel.close()
        srv_transport.close()
        srv_tcpsock.close()

        # --- close channel/transport to NETCONF client ----------------------
        channel.close()
        transport.close()


class ssh_server(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        log.debug("ssh_server.check_channel_request(kind=%s, chanid=%s)",  kind, chanid)
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log.debug("ssh_server.check_auth_password(username=%s, password=%s)", username, password)
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        log.debug("ssh_server.check_auth_publickey()")
        log.critical('Public key authentication is NOT supported')
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        log.debug("ssh_server.get_allowed_auths(username=%s)", username)
        return 'password'

    def check_channel_shell_request(self, channel):
        log.debug("ssh_server.check_channel_shell_request()")
        log.critical('SHELL request is NOT supported')
        self.event.set()
        return False

    def check_channel_exec_request(self, channel, command):
        log.debug("ssh_server.check_channel_exec_request()")
        log.critical('EXEC request is NOT supported')
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        log.debug("ssh_server.check_channel_pty_request(term=%s, width=%d, height=%d)", term, width, height)
        log.critical('PTY request is NOT supported')
        return False

    def check_channel_subsystem_request(self, channel, name):
        log.debug("ssh_server.check_channel_subsystem_request(name=%s)", name)
        if name == 'netconf':
            handler = ncHandler(
                channel, name, self, self.username, self.password)
            handler.start()
            return True
        log.critical('Subsystem %s is NOT supported', name)
        return False


if __name__ == '__main__':
    prog = os.path.splitext(os.path.basename(sys.argv[0]))[0]

    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version=prog + ' ' + __version__)

    group = parser.add_argument_group()
    group.add_argument('-v', '--verbose', action='count', help='enable logging')
    group.add_argument('-d', '--debug', action='count', help='enable ssh-lib logging')
    group.add_argument('--logfile', metavar='filename', type=argparse.FileType('wb', 0), help='trace/debug log (default: <stderr>)')
    group.add_argument('--serverlog', metavar='filename', default='-', type=argparse.FileType('wb', 0), help='server log (default: <stdout>)')
    group.add_argument('--clientlog', metavar='filename', default='-', type=argparse.FileType('wb', 0), help='client log (default: <stdout>)')

    group = parser.add_argument_group()
    group.add_argument('--patch', metavar='filename', type=argparse.FileType('r'), help='Patch NETCONF messages (default: <none>)')

    group = parser.add_argument_group()
    group.add_argument('--port', metavar='tcpport', type=int, default=830, help='TCP-port ncproxy is listening')
    group.add_argument('server', metavar='netconf://<hostname>[:port]', default="netconf://127.0.0.1:830", help='Netconf over SSH server')


    options = parser.parse_args()

    # --- setup module logging -----------------------------------------------
    if options.logfile is None:
        loghandler = logging.StreamHandler(sys.stderr)
    else:
        loghandler = logging.StreamHandler(options.logfile)
    timeformat = '%y/%m/%d %H:%M:%S'
    logformat = '%(asctime)s,%(msecs)-3d %(levelname)-8s %(message)s'
    loghandler.setFormatter(logging.Formatter(logformat, timeformat))

    log = logging.getLogger('paramiko')
    if options.debug is None:
        log.setLevel(logging.NOTSET)
        log.addHandler(logging.NullHandler())
    elif options.debug == 1:
        log.setLevel(logging.CRITICAL)
        log.addHandler(loghandler)
    elif options.debug == 2:
        log.setLevel(logging.ERROR)
        log.addHandler(loghandler)
    elif options.debug == 3:
        log.setLevel(logging.WARNING)
        log.addHandler(loghandler)
    elif options.debug == 4:
        log.setLevel(logging.INFO)
        log.addHandler(loghandler)
    else:
        log.setLevel(logging.DEBUG)
        log.addHandler(loghandler)

    log = logging.getLogger('ncproxy')
    if options.verbose is None:
        log.setLevel(logging.NOTSET)
        log.addHandler(logging.NullHandler())
    elif options.verbose == 1:
        log.setLevel(logging.CRITICAL)
        log.addHandler(loghandler)
    elif options.verbose == 2:
        log.setLevel(logging.ERROR)
        log.addHandler(loghandler)
    elif options.verbose == 3:
        log.setLevel(logging.WARNING)
        log.addHandler(loghandler)
    elif options.verbose == 4:
        log.setLevel(logging.INFO)
        log.addHandler(loghandler)
    else:
        log.setLevel(logging.DEBUG)
        log.addHandler(loghandler)

    # --- set server/client log ----------------------------------------------
    serverlog = options.serverlog
    clientlog = options.clientlog

    # --- parse server URL ---------------------------------------------------
    if options.server.find('://') == -1:
        url = urlparse("netconf://" + options.server)
    else:
        url = urlparse(options.server)

    if url.scheme != "netconf":
        log.critical('Connection to NETCONF server(s) only')
        sys.exit(1)

    # --- parse server URL ---------------------------------------------------
    if options.patch:
        rules = json.load(options.patch)
        for rule in rules['server-msg-modifier']:
            if rule.has_key('patch-file'):
                with open(rule['patch-file'], 'r') as file:
                    rule['patch'] = file.read()
            rule['regex'] = re.compile(rule['match'], re.MULTILINE)

        for rule in rules['client-msg-modifier']:
            if rule.has_key('patch-file'):
                with open(rule['patch-file'], 'r') as file:
                    rule['patch'] = file.read()
            rule['regex'] = re.compile(rule['match'], re.MULTILINE)

        for rule in rules['auto-respond']:
            if rule.has_key('response-file'):
                with open(rule['response-file'], 'r') as file:
                    rule['response'] = file.read()
            rule['regex'] = re.compile(rule['match'], re.MULTILINE)
    else:
        rules = {}
        rules['server-msg-modifier'] = []
        rules['client-msg-modifier'] = []
        rules['auto-respond'] = []

    # --- waiting for incoming client connections ----------------------------
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(None)
        sock.bind(('', options.port))
        sock.listen(100)
        log.info('Listening for client connection ...')
    except Exception as e:
        log.critical('Server setup failed: %s', str(e))
        log.debug(''.join(traceback.format_exception(*sys.exc_info())))
        sys.exit(1)

    # --- handler for incoming client connections ----------------------------
    host_key = paramiko.RSAKey.generate(1024)
    log.debug('Server Key: %s', binascii.hexlify(host_key.get_fingerprint()))

    while True:
        try:
            client, addr = sock.accept()
            log.info("Incoming client connection from %s (srcport: %d)", addr[0], addr[1])
        except (KeyboardInterrupt, SystemExit):
            log.info('ncproxy terminated by user')
            sys.exit(1)
        except Exception as e:
            log.critical('Server listen failure: %s', str(e))
            log.debug(''.join(traceback.format_exception(*sys.exc_info())))
            sys.exit(1)

        try:
            t = paramiko.Transport(client)
            t.load_server_moduli()
            t.add_server_key(host_key)
            t.set_subsystem_handler('netconf', ncHandler)
            t.start_server(server=ssh_server())
        except Exception as e:
            log.warning('Connection failed: %s', str(e))

# EOF
